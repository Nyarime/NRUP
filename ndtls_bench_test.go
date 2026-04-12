package nrup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func BenchmarkDTLSRecordFormat(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	data := make([]byte, 200)
	var seq uint64

	b.SetBytes(200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		io.ReadFull(rand.Reader, nonce)
		encrypted := aead.Seal(nil, nonce, data, nil)
		payload := append(nonce, encrypted...)

		seq++
		record := make([]byte, 13+len(payload))
		record[0] = 23
		binary.BigEndian.PutUint16(record[1:3], 0xFEFD)
		binary.BigEndian.PutUint16(record[3:5], 1)
		binary.BigEndian.PutUint16(record[11:13], uint16(len(payload)))
		copy(record[13:], payload)
		_ = record
	}
}

func BenchmarkNDTLSWrite(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	conn, _ := net.ListenUDP("udp", nil)
	defer conn.Close()

	target, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	cfg := DefaultConfig()
	cfg.MaxBandwidthMbps = 10000 // 10Gbps避免CC阻塞
	ndtls, _ := NewNDTLS(conn, target, key, cfg)

	data := make([]byte, 200)
	rand.Read(data)

	b.SetBytes(200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ndtls.Write(data)
	}
}
