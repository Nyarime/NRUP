package nrup

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Config NRUP配置
type Config struct {
	FECData      int
	FECParity    int
	MaxBandwidthMbps int64 // BBR起步参考值(Mbps)，不是限速。BBR会自动探测实际带宽。0=从小窗口慢启动
	Insecure     bool
	CertFile     string
	KeyFile      string
	Cipher       CipherType // auto/aes-256-gcm/chacha20-poly1305/xchacha20-poly1305
	PSK          []byte // 预共享密钥（防MITM，可选）
	ResumeID     string // 上次连接的SessionID（0-RTT恢复用）
	AuthMode     string // "psk"(默认) 或 "ed25519"
	PrivateKey   []byte // Ed25519私钥(64字节)
	PeerPublicKey []byte // 对方Ed25519公钥(32字节)
	CertDER       []byte // TLS证书DER格式(嵌入DTLS ServerHello，伪装用)

	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	StreamMode       bool
}

func DefaultConfig() *Config {
	return &Config{
		FECData:          10,
		FECParity:        3,
		HandshakeTimeout: 10 * time.Second,
		IdleTimeout:      120 * time.Second,
	}
}

// Conn NRUP连接
type Conn struct {
	dtls       net.Conn
	fec        *FECCodec
	cc         *CongestionController
	seq        *SeqTracker
	adaptive   *AdaptiveFEC
	retransmit *RetransmitQueue
	closed     atomic.Bool
	bytesSent  atomic.Int64
	bytesRecv  atomic.Int64
	pktsSent   atomic.Int64
	pktsRecv   atomic.Int64
	streamMode bool
	writeMu    sync.Mutex
	readBuf    []byte
	sessionID  string // 连接迁移用
}

// Write 发送数据
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.streamMode {
		return c.dtls.Write(p)
	}
	// 自适应调整FEC比例
	c.adaptive.RecordSent(1)
	if c.adaptive.sent >= 100 {
		data, parity := c.adaptive.Adjust()
		if data != c.fec.dataShards || parity != c.fec.parityShards {
			c.fec = NewFECCodec(data, parity)
		}
	}

	// FEC编码
	frames := c.fec.Encode(p)

	// 记录到重传队列
	seq := c.fec.seqNum.Load()
	rto := c.seq.AvgRTT() * 3
	if rto < 200*time.Millisecond {
		rto = 200 * time.Millisecond
	}
	c.retransmit.Add(seq, frames, rto)
	c.seq.OnSend(seq)

	// 发送所有分片
	for _, frame := range frames {
		c.cc.Wait(len(frame))
		c.dtls.Write(frame)
	}

	c.bytesSent.Add(int64(len(p)))
	c.pktsSent.Add(1)
	return len(p), nil
}

// Read 接收数据
func (c *Conn) Read(p []byte) (int, error) {
	if c.streamMode {
		return c.dtls.Read(p)
	}
	for {
		if c.readBuf == nil { c.readBuf = make([]byte, 65536) }
		buf := c.readBuf
		n, err := c.dtls.Read(buf)
		if err != nil {
			return 0, err
		}

		// 判断帧类型
		if n > 0 {
			switch buf[0] {
			case FrameACK:
				// 处理ACK
				ack := DecodeACKFrame(buf[:n])
				if ack != nil {
					rtt := c.seq.OnRecvACK(ack.AckSeq)
					c.cc.OnACK(int64(n), rtt)
				// 反馈RTT给FEC自适应
				c.adaptive.RTT = rtt
					c.retransmit.ACK(ack.AckSeq)
				}
				continue

			case FramePing:
				// 回复Ping
				continue

			case FrameData:
				// 数据帧 → 发ACK + FEC解码
				df := DecodeDataFrame(buf[:n])
				if df != nil {
					// 回ACK
					ackFrame := EncodeACKFrame(df.Seq, 0)
					c.dtls.Write(ackFrame)
				}
				decoded := c.fec.Decode(buf[:n])
				if decoded != nil {
					c.bytesRecv.Add(int64(len(decoded)))
					copy(p, decoded)
					return len(decoded), nil
				}
				continue
			}
		}

		// 旧格式兼容
		decoded := c.fec.Decode(buf[:n])
		if decoded != nil {
			c.bytesRecv.Add(int64(len(decoded)))
				copy(p, decoded)
			return len(decoded), nil
		}
	}
}

// Close 关闭
func (c *Conn) Close() error {
	c.closed.Store(true)
	return c.dtls.Close()
}

// RemoteAddr 远端地址
func (c *Conn) RemoteAddr() net.Addr { return c.dtls.RemoteAddr() }
// LocalAddr 本地地址
func (c *Conn) LocalAddr() net.Addr  { return c.dtls.LocalAddr() }
// SetDeadline 设置超时
func (c *Conn) SetDeadline(t time.Time) error      { return c.dtls.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.dtls.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.dtls.SetWriteDeadline(t) }

// Stats 获取统计
func (c *Conn) Stats() ConnStats {
	sent, lost, rtt, lossRate := c.seq.Stats()
	return ConnStats{
		Sent:        sent,
		Lost:        lost,
		RTT:         rtt,
		LossRate:    lossRate,
		RetransmitQ:   c.retransmit.Size(),
		BytesSent:     c.bytesSent.Load(),
		BytesReceived: c.bytesRecv.Load(),
	}
}

type ConnStats struct {
	Sent        int
	Lost        int
	RTT         time.Duration
	LossRate    float64
	RetransmitQ   int
	Cwnd          int64
	PacingRate    int64
	State         string
	BytesSent     int64
	BytesReceived int64
}

// startRetransmitLoop 后台重传循环
func (c *Conn) startRetransmitLoop() {
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		for range ticker.C {
			if c.closed.Load() {
				return
			}
			expired := c.retransmit.GetExpired()
			for _, r := range expired {
				for _, frame := range r.Frames {
					c.dtls.Write(frame) //nolint:errcheck retransmit
				}
				c.adaptive.RecordLoss(1)
			}
		}
	}()
}

// ConnStats 连接统计

// Migrate 连接迁移（IP变化时调用）
// 保持session不变，只更新底层UDP地址
func (c *Conn) Migrate(newAddr net.Addr) {
	if dtls, ok := c.dtls.(*NDTLSConn); ok {
		dtls.UpdateRemoteAddr(newAddr)
	}
}

// SessionID 获取连接session ID
func (c *Conn) SessionID() string {
	return c.sessionID
}

// DiscoverMTU 探测路径MTU
func (c *Conn) DiscoverMTU() int {
	if dtls, ok := c.dtls.(*NDTLSConn); ok {
		for mtu := 1500; mtu >= 500; mtu -= 100 {
			probe := make([]byte, mtu)
			probe[0] = FramePing
			_, err := dtls.Write(probe)
			if err == nil {
				return mtu - 41 // 减去NRUP开销(13 header + 12 nonce + 16 tag)
			}
		}
	}
	return 1200 // 安全默认值
}
