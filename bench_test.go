package nrup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"net"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func BenchmarkFECEncode(b *testing.B) {
	fec := NewFECCodec(10, 3)
	data := make([]byte, 1400) // 典型MTU大小
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fec.Encode(data)
	}
}

func BenchmarkFECDecode(b *testing.B) {
	fec := NewFECCodec(10, 3)
	data := make([]byte, 1400)
	frames := fec.Encode(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fec2 := NewFECCodec(10, 3)
		for _, f := range frames {
			result := fec2.Decode(f)
			if result != nil {
				break
			}
		}
	}
}

func BenchmarkCongestionWait(b *testing.B) {
	cc := NewCongestionController(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc.Wait(100)
		cc.OnACK(100, 0)
	}
}

func BenchmarkAESGCMEncrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	data := make([]byte, 200) // 游戏包

	b.SetBytes(200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(nonce[:0], nonce, data, nil)
	}
}

func BenchmarkNDTLSWrite(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	sAddr, _ := net.ResolveUDPAddr("udp", ":19890")
	sConn, err := net.ListenUDP("udp", sAddr)
	if err != nil {
		b.Skip("port")
		return
	}
	defer sConn.Close()

	rAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:19890")
	mc, _ := NewNDTLS(sConn, rAddr, key, &Config{FECData: 1, FECParity: 0})
	data := make([]byte, 200)

	b.SetBytes(200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mc.Write(data)
	}
}

func BenchmarkChaCha20Encrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, _ := chacha20poly1305.New(key)
	nonce := make([]byte, aead.NonceSize())
	data := make([]byte, 200)
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(nonce, nonce, data, nil)
	}
}
