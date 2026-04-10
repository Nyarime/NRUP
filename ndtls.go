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
		cc:         NewCongestionController(cfg.MaxBandwidth),
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

	// AES-GCM加密
	nonce := make([]byte, mc.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return 0, err }
	encrypted := mc.aead.Seal(nil, nonce, p, nil)

	// 构造DTLS记录
	seqNum := mc.writeSeq.Add(1)
	payload := append(nonce, encrypted...)

	record := make([]byte, recordHeaderLen+len(payload))
	record[0] = contentAppData                                    // ContentType
	binary.BigEndian.PutUint16(record[1:3], dtlsVersion)         // Version
	binary.BigEndian.PutUint16(record[3:5], mc.writeEpoch)       // Epoch
	// 6-byte sequence number
	record[5] = byte(seqNum >> 40)
	record[6] = byte(seqNum >> 32)
	record[7] = byte(seqNum >> 24)
	record[8] = byte(seqNum >> 16)
	record[9] = byte(seqNum >> 8)
	record[10] = byte(seqNum)
	binary.BigEndian.PutUint16(record[11:13], uint16(len(payload))) // Length
	copy(record[13:], payload)

	// 拥塞控制
	mc.cc.Wait(len(record))

	// 发送
	_, err := mc.udpConn.WriteTo(record, mc.remoteAddr)
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
	payloadLen := binary.BigEndian.Uint16(buf[11:13])

	if contentType != contentAppData || version != dtlsVersion {
		return 0, errors.New("invalid DTLS record")
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
