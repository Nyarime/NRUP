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
	MaxBandwidth int64
	Insecure     bool
	CertFile     string
	KeyFile      string
	Cipher       CipherType // auto/aes-256-gcm/chacha20-poly1305/xchacha20-poly1305

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
	bytesSent atomic.Int64
	bytesRecv atomic.Int64
	pktsSent  atomic.Int64
	pktsRecv  atomic.Int64
	streamMode bool
	writeMu    sync.Mutex
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
		bufPtr := GetLargeBuf()
		buf := *bufPtr
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
					c.retransmit.ACK(ack.AckSeq)
				}
				continue

			case FramePing:
				// 回复Ping
				continue

			case FrameData:
				// 数据帧 → FEC解码
				decoded := c.fec.Decode(buf[:n])
				if decoded != nil {
				PutLargeBuf(bufPtr)
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
				PutLargeBuf(bufPtr)
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
