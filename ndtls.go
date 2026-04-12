package nrup

import (
	"crypto/rand"
	"encoding/binary"
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// nDTLS 最小DTLS实现
// 只实现记录层格式（让GFW看到标准DTLS）
// 内部用AES-256-GCM加密
//
// DTLS 1.2 Record Layer:
// [1B ContentType][2B Version=0xFEFD][2B Epoch][6B SeqNum][2B Length][Payload]

const (
	dtlsVersion     = 0xFEFD // DTLS 1.2
	contentAppData   = 23     // application_data
	contentHandshake = 22     // handshake
	recordHeaderLen  = 13     // DTLS record header
)

// NDTLSConn 最小DTLS连接
type NDTLSConn struct {
	udpConn    net.PacketConn
	remoteAddr net.Addr
	aead       cipher.AEAD
	
	writeEpoch uint16
	writeSeq   atomic.Uint64
	readSeq    uint64

	fec        *FECCodec
	cc         *CongestionController
	seq        *SeqTracker
	adaptive   *AdaptiveFEC
	retransmit *RetransmitQueue
	closed     atomic.Bool
	writeMu    sync.Mutex
	replay     replayWindow
}

// NewNDTLS 创建最小DTLS连接
func NewNDTLS(conn net.PacketConn, remoteAddr net.Addr, key []byte, cfg *Config) (*NDTLSConn, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	aead, err := newAEAD(key, cfg.Cipher)
	if err != nil {
		return nil, err
	}

	mc := &NDTLSConn{
		udpConn:    conn,
		remoteAddr: remoteAddr,
		aead:       aead,
		writeEpoch: 1,
		fec:        NewFECCodec(cfg.FECData, cfg.FECParity),
		cc:         NewCongestionController(cfg.MaxBandwidthMbps * 1000000 / 8),
		seq:        NewSeqTracker(),
		adaptive:   NewAdaptiveFEC(cfg.FECData, cfg.FECParity),
		retransmit: NewRetransmitQueue(),
	}
	return mc, nil
}

// Write 发送数据（DTLS记录格式 + AES-GCM加密）
func (mc *NDTLSConn) Write(p []byte) (int, error) {
	mc.writeMu.Lock()
	defer mc.writeMu.Unlock()

	nonceSize := mc.aead.NonceSize()
	overhead := mc.aead.Overhead()
	payloadLen := nonceSize + len(p) + overhead
	totalLen := recordHeaderLen + payloadLen

	// 单次分配：record header + nonce + ciphertext
	buf := make([]byte, totalLen)

	// nonce
	nonce := buf[recordHeaderLen : recordHeaderLen+nonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return 0, err }

	// 加密（直接写入buf）
	mc.aead.Seal(buf[recordHeaderLen+nonceSize:recordHeaderLen+nonceSize], nonce, p, nil)

	// DTLS记录头
	seqNum := mc.writeSeq.Add(1)
	buf[0] = contentAppData
	binary.BigEndian.PutUint16(buf[1:3], dtlsVersion)
	binary.BigEndian.PutUint16(buf[3:5], mc.writeEpoch)
	buf[5] = byte(seqNum >> 40)
	buf[6] = byte(seqNum >> 32)
	buf[7] = byte(seqNum >> 24)
	buf[8] = byte(seqNum >> 16)
	buf[9] = byte(seqNum >> 8)
	buf[10] = byte(seqNum)
	binary.BigEndian.PutUint16(buf[11:13], uint16(payloadLen))

	mc.cc.Wait(totalLen)

	_, err := mc.udpConn.WriteTo(buf, mc.remoteAddr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read 接收数据（解析DTLS记录 + AES-GCM解密）
func (mc *NDTLSConn) Read(p []byte) (int, error) {
	buf := make([]byte, 65536)
	n, _, err := mc.udpConn.ReadFrom(buf)
	if err != nil {
		return 0, err
	}

	if n < recordHeaderLen {
		return 0, errors.New("record too short")
	}

	// 验证DTLS记录头
	contentType := buf[0]
	version := binary.BigEndian.Uint16(buf[1:3])
	// 提取序列号（48位）
	recvSeq := uint64(buf[5])<<40 | uint64(buf[6])<<32 | uint64(buf[7])<<24 |
		uint64(buf[8])<<16 | uint64(buf[9])<<8 | uint64(buf[10])
	payloadLen := binary.BigEndian.Uint16(buf[11:13])

	if contentType != contentAppData || version != dtlsVersion {
		return 0, errors.New("invalid DTLS record")
	}

	// 防重放检查
	if !mc.replay.Check(recvSeq) {
		return 0, errors.New("replay detected")
	}

	if int(payloadLen)+recordHeaderLen > n {
		return 0, errors.New("truncated record")
	}

	payload := buf[recordHeaderLen : recordHeaderLen+int(payloadLen)]

	// AES-GCM解密
	if len(payload) < mc.aead.NonceSize() {
		return 0, errors.New("payload too short")
	}
	nonce := payload[:mc.aead.NonceSize()]
	ciphertext := payload[mc.aead.NonceSize():]

	plaintext, err := mc.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	copy(p, plaintext)
	return len(plaintext), nil
}

func (mc *NDTLSConn) Close() error {
	mc.closed.Store(true)
	return mc.udpConn.Close()
}

func (mc *NDTLSConn) RemoteAddr() net.Addr                    { return mc.remoteAddr }
func (mc *NDTLSConn) LocalAddr() net.Addr                     { return mc.udpConn.LocalAddr() }
func (mc *NDTLSConn) SetDeadline(t time.Time) error           { return nil }
func (mc *NDTLSConn) SetReadDeadline(t time.Time) error       { return nil }
func (mc *NDTLSConn) SetWriteDeadline(t time.Time) error      { return nil }

// Overhead 每包额外开销
func (mc *NDTLSConn) Overhead() int {
	return recordHeaderLen + mc.aead.NonceSize() + mc.aead.Overhead()
	// 13 + 12 + 16 = 41 bytes
}

// UpdateRemoteAddr 更新远端地址（连接迁移）
func (mc *NDTLSConn) UpdateRemoteAddr(addr net.Addr) {
	mc.writeMu.Lock()
	mc.remoteAddr = addr
	mc.writeMu.Unlock()
}

// RemoteAddr 获取远端地址
func (mc *NDTLSConn) RemoteAddrInfo() net.Addr {
	return mc.remoteAddr
}

// replayWindow 防重放窗口（64位bitmap）
type replayWindow struct {
	maxSeq uint64
	bitmap uint64 // 覆盖maxSeq前64个序列号
}

func (rw *replayWindow) Check(seq uint64) bool {
	if seq > rw.maxSeq {
		// 新序列号，滑动窗口
		shift := seq - rw.maxSeq
		if shift >= 64 {
			rw.bitmap = 0
		} else {
			rw.bitmap <<= shift
		}
		rw.maxSeq = seq
		rw.bitmap |= 1
		return true
	}

	// 旧序列号，检查是否在窗口内
	diff := rw.maxSeq - seq
	if diff >= 64 {
		return false // 太旧，拒绝
	}

	mask := uint64(1) << diff
	if rw.bitmap&mask != 0 {
		return false // 已收过，重放攻击
	}
	rw.bitmap |= mask
	return true
}
