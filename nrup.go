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
	SmallPacketThreshold int // 小包冗余阈值(字节,默认256)
	SmoothedLossAlpha   float64 // EWMA系数(默认0.28)

	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	StreamMode       bool
	FECType       FECType  // rs(默认) / raptorq / ldpc
	SACKInterval     int // SACK频率(每N包发一次，默认3)
}

func DefaultConfig() *Config {
	return &Config{
		FECData:          8,
		FECParity:        4,
		HandshakeTimeout: 10 * time.Second,
		IdleTimeout:      120 * time.Second,
		SmallPacketThreshold: 256,
		SmoothedLossAlpha:   0.28,
	}
}

// Conn NRUP连接
type Conn struct {
	cfg        *Config
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
	streamEnc  *StreamEncoder
	sackCount  int // SACK频率控制
	mtu        int // 缓存的MTU(动态探测)
	ackBatch   []ACKFrame // v1.4.3: 批量ACK缓冲
	smoothedLoss float64 // EWMA平滑丢包率
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
	threshold := c.smallThreshold(); if len(p) < threshold {
		seq := uint32(c.pktsSent.Add(1))
		// [FrameData][4B seq][data]
		pkt := make([]byte, 1+4+len(p))
		pkt[0] = FrameData
		pkt[1] = byte(seq >> 24)
		pkt[2] = byte(seq >> 16)
		pkt[3] = byte(seq >> 8)
		pkt[4] = byte(seq)
		copy(pkt[5:], p)
		// 自适应冗余：根据实时丢包率动态调整副本数
		redundancy := 2
		m := c.GetMetrics()
		alpha := c.smoothAlpha(); c.smoothedLoss = (1-alpha)*c.smoothedLoss + alpha*m.LossRate
		switch {
		case c.smoothedLoss > 0.50:
			redundancy = 5
		case c.smoothedLoss > 0.35:
			redundancy = 4
		case c.smoothedLoss > 0.20:
			redundancy = 3
		default:
			redundancy = 2
		}
		for i := 0; i < redundancy; i++ {
			c.dtls.Write(pkt)
		}
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

	// 大包分片：每片≤maxChunk字节，确保FEC shard不超MTU
	const maxChunk = 1024
	for off := 0; off < len(p); off += maxChunk {
		end := off + maxChunk
		if end > len(p) { end = len(p) }
		chunk := p[off:end]

		frames := c.fec.Encode(chunk)
		seq := c.fec.seqNum.Load()
		rto := c.seq.AvgRTT() * 3
		if rto < 200*time.Millisecond { rto = 200 * time.Millisecond }
		c.retransmit.Add(seq, frames, rto)
		c.seq.OnSend(seq)

		for _, frame := range frames {
			tagged := append([]byte{FrameData}, frame...)
			c.cc.Wait(len(tagged))
			c.dtls.Write(tagged)
		}
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
				c.processACK(DecodeACKFrame(buf[:n]))
				continue

			case FrameBatchACK:
				for _, ack := range DecodeBatchACK(buf[:n]) {
					c.processACK(&ack)
				}
				continue

			case FrameClose:
				c.closed.Store(true)
				return 0, net.ErrClosed
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
					// 每3个包发一次SACK（减少ACK流量）
					c.sackCount++
					interval := 3
					if c.cfg != nil && c.cfg.SACKInterval > 0 { interval = c.cfg.SACKInterval }
					// v1.4.3: 批量ACK
					c.ackBatch = append(c.ackBatch, ACKFrame{AckSeq: seq, Bitmap: c.buildSACKBitmap(seq)})
					if c.sackCount >= interval {
						if len(c.ackBatch) > 1 {
							c.dtls.Write(EncodeBatchACK(c.ackBatch))
						} else {
							c.dtls.Write(EncodeACKFrame(seq, c.buildSACKBitmap(seq)))
						}
						c.ackBatch = c.ackBatch[:0]
						c.sackCount = 0
					}
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
	// FEC统计
	var fecD, fecR, fecL int64
	var fecEff float64
	if c.fec != nil {
		fecD, fecR, fecL = c.fec.FECStats()
		fecEff = c.fec.FECEffectiveness()
	}
	var parity int
	if c.adaptive != nil { parity = c.adaptive.ParityShards }
	return ConnStats{
		Sent:        sent,
		Lost:        lost,
		RTT:         rtt,
		LossRate:    lossRate,
		RetransmitQ:   c.retransmit.Size(),
		BytesSent:     c.bytesSent.Load(),
		BytesReceived: c.bytesRecv.Load(),
		FECDecodes:      fecD,
		FECRecovered:    fecR,
		FECLostShards:   fecL,
		FECEffectiveness: fecEff,
		CurrentParity:   parity,
		MTU:             c.mtu,
		Jitter:          c.seq.Jitter(),
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
	// v1.4.2: FEC + SACK统计
	FECDecodes      int64   // FEC解码总次数
	FECRecovered    int64   // FEC恢复丢失shard次数
	FECLostShards   int64   // 总丢失shard数
	FECEffectiveness float64 // FEC有效性(0.0~1.0)
	CurrentParity   int     // 当前FEC冗余分片数
	MTU             int     // 探测的MTU
	Jitter          time.Duration // RTT抖动
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

// DiscoverMTU 探测路径MTU（结果缓存）
func (c *Conn) DiscoverMTU() int {
	if c.mtu > 0 { return c.mtu } // 缓存
	if dtls, ok := c.dtls.(*NDTLSConn); ok {
		for mtu := 1500; mtu >= 500; mtu -= 100 {
			probe := make([]byte, mtu)
			probe[0] = FramePing
			_, err := dtls.Write(probe)
			if err == nil {
				c.mtu = mtu - 41 // NRUP开销(13+12+16)
				return c.mtu
			}
		}
	}
	c.mtu = 1200
	return c.mtu
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
	FECEffectiveness float64 `json:"fec_effectiveness"`
	CurrentParity int     `json:"current_parity"`
	LossRate      float64 `json:"loss_rate"`
	SmoothedLoss  float64 `json:"smoothed_loss"`
}

// GetMetrics 获取连接指标
func (c *Conn) GetMetrics() Metrics {
	var fecEff float64
	var fecRec int64
	var parity int
	if c.fec != nil {
		_, fecRec, _ = c.fec.FECStats()
		fecEff = c.fec.FECEffectiveness()
	}
	if c.adaptive != nil { parity = c.adaptive.ParityShards }
	return Metrics{
		PacketsSent:  c.pktsSent.Load(),
		PacketsRecv:  c.pktsRecv.Load(),
		BytesSent:    c.bytesSent.Load(),
		BytesRecv:    c.bytesRecv.Load(),
		FECRecovery:  fecRec,
		FECEffectiveness: fecEff,
		CurrentParity: parity,
		SmoothedLoss: c.smoothedLoss,
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

func (c *Conn) smallThreshold() int {
	if c.cfg != nil && c.cfg.SmallPacketThreshold > 0 {
		return c.cfg.SmallPacketThreshold
	}
	return 256
}

// CloseGraceful 优雅关闭（通知对端）
func (c *Conn) CloseGraceful() error {
	// Flush流式FEC剩余数据
	if c.streamEnc != nil {
		if frames := c.streamEnc.Flush(); frames != nil {
			for _, f := range frames {
				c.dtls.Write(f)
			}
		}
	}
	// 发送关闭帧
	c.dtls.Write([]byte{FrameClose})
	c.dtls.Write([]byte{FrameClose})
	time.Sleep(50 * time.Millisecond)
	c.closed.Store(true)
	return c.dtls.Close()
}

// dynamicFECParams 根据实时丢包率计算FEC参数
func dynamicFECParams(lossRate float64) (data, parity int) {
	switch {
	case lossRate > 0.45:
		return 6, 6 // 1:1保护
	case lossRate > 0.30:
		return 7, 5
	case lossRate > 0.20:
		return 8, 4
	case lossRate > 0.10:
		return 9, 3
	default:
		return 10, 2
	}
}

func (c *Conn) smoothAlpha() float64 {
	if c.cfg != nil && c.cfg.SmoothedLossAlpha > 0 {
		return c.cfg.SmoothedLossAlpha
	}
	return 0.28
}

// buildSACKBitmap 构建SACK位图(v1.4.1: 32位，后续可升级uint64)（标记后续32个seq的接收状态）
func (c *Conn) buildSACKBitmap(baseSeq uint32) uint32 {
	var bitmap uint32
	for i := uint32(1); i <= 32; i++ {
		if c.smallPktSeen(baseSeq + i) {
			bitmap |= 1 << (i - 1)
		}
	}
	return bitmap
}

// processACK 处理单个ACK(含SACK bitmap)
func (c *Conn) processACK(ack *ACKFrame) {
	if ack == nil { return }
	rtt := c.seq.OnRecvACK(ack.AckSeq)
	c.cc.OnACK(int64(9), rtt)
	c.adaptive.RTT = rtt
	c.retransmit.UpdateJitter(c.seq.Jitter())
	c.retransmit.ACK(ack.AckSeq)
	if ack.Bitmap != 0 {
		for i := uint32(0); i < 32; i++ {
			if ack.Bitmap&(1<<i) != 0 {
				c.retransmit.ACK(ack.AckSeq + i + 1)
			}
		}
	}
}
