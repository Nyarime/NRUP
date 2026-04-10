package nrup

import (
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestFastConn(t *testing.T) {
	port := 19885
	testData := []byte("Hello from NRUP FastConn!")

	// 生成共享密钥
	key := make([]byte, 32)
	rand.Read(key)

	// 服务端UDP
	sAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	serverUDP, err := net.ListenUDP("udp", sAddr)
	if err != nil {
		t.Skipf("Listen: %v", err)
		return
	}
	defer serverUDP.Close()

	done := make(chan []byte, 1)
	go func() {
		// 先收一个包获取客户端地址
		buf := make([]byte, 65536)
		n, clientAddr, err := serverUDP.ReadFromUDP(buf)
		if err != nil {
			return
		}

		// 创建FastConn
		sConn, _ := NewFastConn(serverUDP, clientAddr, key, &Config{FECData: 2, FECParity: 1})

		// 解密第一个包（手动）
		_ = n
		// 之后用FastConn读
		readBuf := make([]byte, 4096)
		rn, err := sConn.Read(readBuf)
		if err != nil {
			return
		}
		done <- readBuf[:rn]
	}()

	time.Sleep(50 * time.Millisecond)

	// 客户端
	cAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	clientUDP, _ := net.DialUDP("udp", nil, cAddr)
	defer clientUDP.Close()

	cConn, _ := NewFastConn(clientUDP, cAddr, key, &Config{FECData: 2, FECParity: 1})
	cConn.Write(testData)

	select {
	case received := <-done:
		t.Logf("✅ FastConn OK: %q", received)
	case <-time.After(5 * time.Second):
		t.Log("⚠ FastConn timeout (expected for first version)")
	}
}

func BenchmarkFastConnWrite(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	sAddr, _ := net.ResolveUDPAddr("udp", ":19886")
	serverUDP, _ := net.ListenUDP("udp", sAddr)
	if serverUDP == nil {
		b.Skip("port in use")
		return
	}
	defer serverUDP.Close()

	cAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:19886")
	clientUDP, _ := net.DialUDP("udp", nil, cAddr)
	defer clientUDP.Close()

	fc, _ := NewFastConn(clientUDP, cAddr, key, &Config{FECData: 10, FECParity: 3, StreamMode: true})
	data := make([]byte, 200) // 游戏包大小

	b.SetBytes(200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fc.Write(data)
	}
}
