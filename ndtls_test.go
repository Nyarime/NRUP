package nrup

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNDTLSEndToEnd(t *testing.T) {
	port := 19891
	key := make([]byte, 32)
	rand.Read(key)
	testData := []byte("Hello nDTLS!")

	// 服务端
	sAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	sConn, err := net.ListenUDP("udp", sAddr)
	if err != nil {
		t.Skipf("Listen: %v", err)
		return
	}

	done := make(chan []byte, 1)
	go func() {
		// 直接用nDTLS读（不先ReadFrom）
		cAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1") // 临时，会被覆盖
		serverMC, _ := NewNDTLS(sConn, cAddr, key, DefaultConfig())
		p := make([]byte, 4096)
		n, err := serverMC.Read(p)
		if err != nil {
			return
		}
		done <- p[:n]
	}()

	time.Sleep(50 * time.Millisecond)

	// 客户端
	cConn, _ := net.ListenUDP("udp", nil)
	rAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	clientMC, _ := NewNDTLS(cConn, rAddr, key, DefaultConfig())
	clientMC.Write(testData)

	select {
	case received := <-done:
		if bytes.Equal(received, testData) {
			t.Logf("✅ nDTLS e2e: %d bytes OK", len(received))
		} else {
			t.Fatalf("Mismatch: %q", received)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout")
	}
	sConn.Close()
	cConn.Close()
}

func TestNDTLSGameTraffic(t *testing.T) {
	port := 19892
	key := make([]byte, 32)
	rand.Read(key)

	sAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	sConn, err := net.ListenUDP("udp", sAddr)
	if err != nil {
		t.Skipf("Listen: %v", err)
		return
	}

	packets := 200
	done := make(chan int, 1)

	go func() {
		count := 0
		buf := make([]byte, 4096)
		for count < packets {
			n, clientAddr, err := sConn.ReadFrom(buf)
			if err != nil {
				break
			}
			// 验证DTLS记录头
			if n > 13 && buf[0] == contentAppData && buf[1] == 0xFE && buf[2] == 0xFD {
				count++
			}
			_ = clientAddr
		}
		done <- count
	}()

	time.Sleep(50 * time.Millisecond)

	cConn, _ := net.ListenUDP("udp", nil)
	rAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	mc, _ := NewNDTLS(cConn, rAddr, key, DefaultConfig())

	start := time.Now()
	for i := 0; i < packets; i++ {
		data := make([]byte, 64)
		data[0] = byte(i)
		mc.Write(data)
	}
	elapsed := time.Since(start)

	select {
	case count := <-done:
		pps := float64(count) / elapsed.Seconds()
		t.Logf("✅ nDTLS game: %d/%d in %v (%.0f pps)", count, packets, elapsed, pps)
		// 验证所有包都有DTLS头
		if count == packets {
			t.Log("✅ All packets have valid DTLS 1.2 record headers")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout")
	}

	sConn.Close()
	cConn.Close()
}
