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
	CertDER       []byte // TLS证书DER格式(嵌入DTLS ServerHello)
	Disguise      string // 伪装模式: "anyconnect"(默认) / "quic"
	DisguiseSNI   string // QUIC伪装时嵌入的SNI
	Logger        Logger // 日志接口(默认静默)

	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	StreamMode       bool
}

func DefaultConfig() *Config {
	return &Config{
		FECData:          8,
		FECParity:        4,
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
	seenSmall  map[uint32]bool
	sessionID  string // 连接迁移用
}

// Write 发送数据
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.streamMode {
		return c.dtls.Write(p)
	}

	// 小包优化：数据<256字节时不拆分FEC，直接发2份冗余
	if len(p) < 256 {
		seq := uint32(c.pktsSent.Add(1))
		// [FrameData][4B seq][data]
		pkt := make([]byte, 1+4+len(p))
		pkt[0] = FrameData
		pkt[1] = byte(seq >> 24)
		pkt[2] = byte(seq >> 16)
		pkt[3] = byte(seq >> 8)
		pkt[4] = byte(seq)
		copy(pkt[5:], p)
		c.dtls.Write(pkt)
		c.dtls.Write(pkt) // 冗余副本
		c.bytesSent.Add(int64(len(p)))
		return len(p), nil
	}

	// 自适应调整FEC比例
	c.adaptive.RecordSent(1)
	if c.adaptive.sent >= 30 {
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

	// 发送所有分片（加FrameData前缀）
	for _, frame := range frames {
		c.cc.Wait(len(frame) + 1)
		tagged := append([]byte{FrameData}, frame...)
		c.dtls.Write(tagged)
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
				payload := buf[1:n]
				// 尝试FEC解码
				decoded := c.fec.Decode(payload)
				if decoded != nil {
					c.bytesRecv.Add(int64(len(decoded)))
					c.pktsRecv.Add(1)
					copy(p, decoded)
					return len(decoded), nil
				}
				// 小包模式：带序号去重
				if len(payload) >= 4 && len(payload) < 260 {
					seq := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
					data := payload[4:]
					// 去重：检查是否已收过
					if c.smallPktSeen(seq) {
						continue
					}
					c.bytesRecv.Add(int64(len(data)))
					c.pktsRecv.Add(1)
					copy(p, data)
					return len(data), nil
				}
				continue
			}
		}

		// 未知帧类型，跳过
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
					tagged := append([]byte{FrameData}, frame...)
					c.dtls.Write(tagged)
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

// Logger 日志接口
type Logger interface {
	Debug(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// noopLogger 默认静默日志
type noopLogger struct{}
func (noopLogger) Debug(string, ...interface{}) {}
func (noopLogger) Error(string, ...interface{}) {}

// Metrics 连接指标
type Metrics struct {
	HandshakeOK   int64   `json:"handshake_ok"`
	HandshakeFail int64   `json:"handshake_fail"`
	PacketsSent   int64   `json:"packets_sent"`
	PacketsRecv   int64   `json:"packets_recv"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesRecv     int64   `json:"bytes_recv"`
	RetransmitCount int64 `json:"retransmit_count"`
	FECRecovery   int64   `json:"fec_recovery"`
	LossRate      float64 `json:"loss_rate"`
}

// GetMetrics 获取连接指标
func (c *Conn) GetMetrics() Metrics {
	return Metrics{
		PacketsSent: c.pktsSent.Load(),
		PacketsRecv: c.pktsRecv.Load(),
		BytesSent:   c.bytesSent.Load(),
		BytesRecv:   c.bytesRecv.Load(),
	}
}

// smallPktSeen 小包去重（滑动窗口）
func (c *Conn) smallPktSeen(seq uint32) bool {
	c.writeMu.Lock() // 复用writeMu
	defer c.writeMu.Unlock()
	if c.seenSmall == nil {
		c.seenSmall = make(map[uint32]bool)
	}
	if c.seenSmall[seq] {
		return true
	}
	c.seenSmall[seq] = true
	// 清理旧条目（保留最近1000个）
	if len(c.seenSmall) > 1000 {
		for k := range c.seenSmall {
			delete(c.seenSmall, k)
			if len(c.seenSmall) <= 500 { break }
		}
	}
	return false
}
