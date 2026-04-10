package nrup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"sync"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// FastConn 高性能连接（不用pion/dtls，直接AES-GCM over UDP）
// 密钥通过TCP/TLS侧信道交换（像OpenConnect一样）
type FastConn struct {
	udpConn    *net.UDPConn
	remoteAddr *net.UDPAddr
	aead       cipher.AEAD
	fec        *FECCodec
	cc         *CongestionController
	seq        *SeqTracker
	adaptive   *AdaptiveFEC
	retransmit *RetransmitQueue
	closed     atomic.Bool
	writeMu    sync.Mutex
	readSeq    uint64 // 防重放
}

// NewFastConn 从预共享密钥创建高性能连接
// key: 32字节AES-256密钥（通过TCP/TLS交换）
func NewFastConn(udpConn *net.UDPConn, remoteAddr *net.UDPAddr, key []byte, cfg *Config) (*FastConn, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	fc := &FastConn{
		udpConn:    udpConn,
		remoteAddr: remoteAddr,
		aead:       aead,
		fec:        NewFECCodec(cfg.FECData, cfg.FECParity),
		cc:         NewCongestionController(cfg.MaxBandwidth),
		seq:        NewSeqTracker(),
		adaptive:   NewAdaptiveFEC(cfg.FECData, cfg.FECParity),
		retransmit: NewRetransmitQueue(),
	}
	fc.startRetransmitLoop()
	return fc, nil
}

// Write 加密发送（AES-GCM直接加密，零DTLS开销）
func (fc *FastConn) Write(p []byte) (int, error) {
	fc.writeMu.Lock()
	defer fc.writeMu.Unlock()

	// FEC编码
	fc.adaptive.RecordSent(1)
	frames := fc.fec.Encode(p)

	for _, frame := range frames {
		fc.cc.Wait(len(frame))

		// AES-GCM加密: [12B nonce][encrypted frame][16B tag]
		nonce := make([]byte, fc.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}

		encrypted := fc.aead.Seal(nonce, nonce, frame, nil)

		// 发送
		_, err := fc.udpConn.WriteToUDP(encrypted, fc.remoteAddr)
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Read 解密接收
func (fc *FastConn) Read(p []byte) (int, error) {
	for {
		buf := make([]byte, 65536)
		n, _, err := fc.udpConn.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}

		if n < fc.aead.NonceSize()+fc.aead.Overhead() {
			continue // 包太小
		}

		// AES-GCM解密
		nonce := buf[:fc.aead.NonceSize()]
		ciphertext := buf[fc.aead.NonceSize():n]

		frame, err := fc.aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue // 解密失败=伪造包，丢弃
		}

		// FEC解码
		decoded := fc.fec.Decode(frame)
		if decoded != nil {
			copy(p, decoded)
			return len(decoded), nil
		}
	}
}

func (fc *FastConn) Close() error {
	fc.closed.Store(true)
	return fc.udpConn.Close()
}

func (fc *FastConn) RemoteAddr() net.Addr { return fc.remoteAddr }
func (fc *FastConn) LocalAddr() net.Addr  { return fc.udpConn.LocalAddr() }
func (fc *FastConn) SetDeadline(t time.Time) error      { return fc.udpConn.SetDeadline(t) }
func (fc *FastConn) SetReadDeadline(t time.Time) error  { return fc.udpConn.SetReadDeadline(t) }
func (fc *FastConn) SetWriteDeadline(t time.Time) error { return fc.udpConn.SetWriteDeadline(t) }

func (fc *FastConn) startRetransmitLoop() {
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		for range ticker.C {
			if fc.closed.Load() {
				return
			}
			expired := fc.retransmit.GetExpired()
			for _, r := range expired {
				for _, frame := range r.Frames {
					nonce := make([]byte, fc.aead.NonceSize())
					rand.Read(nonce) //nolint
					encrypted := fc.aead.Seal(nonce, nonce, frame, nil)
					if _, err := fc.udpConn.WriteToUDP(encrypted, fc.remoteAddr); err != nil { return }
				}
				fc.adaptive.RecordLoss(1)
			}
		}
	}()
}

// Stats 统计
func (fc *FastConn) Stats() ConnStats {
	sent, lost, rtt, lossRate := fc.seq.Stats()
	return ConnStats{
		Sent:        sent,
		Lost:        lost,
		RTT:         rtt,
		LossRate:    lossRate,
		RetransmitQ: fc.retransmit.Size(),
	}
}

// EncryptedOverhead 每包加密开销
func (fc *FastConn) EncryptedOverhead() int {
	return fc.aead.NonceSize() + fc.aead.Overhead() // 12 + 16 = 28 bytes
}
