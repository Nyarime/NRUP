package nrup

import (
	"fmt"
	"testing"
	"time"
)

// 大数据传输测试


// 多次小包传输（模拟游戏）
func TestGameTraffic(t *testing.T) {
	port := 19879
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := Listen(fmt.Sprintf(":%d", port), &Config{FECData: 5, FECParity: 2})
	if err != nil {
		t.Skipf("Listen: %v", err)
		return
	}
	defer ln.Close()

	packets := 100
	packetSize := 64 // 游戏包通常很小
	done := make(chan int, 1)

	go func() {
		conn, _ := ln.Accept()
		defer conn.Close()
		count := 0
		buf := make([]byte, 1024)
		for count < packets {
			_, err := conn.Read(buf)
			if err != nil {
				break
			}
			count++
		}
		done <- count
	}()

	time.Sleep(100 * time.Millisecond)
	conn, err := Dial(addr, &Config{FECData: 5, FECParity: 2, Insecure: true})
	if err != nil {
		t.Skipf("Dial: %v", err)
		return
	}
	defer conn.Close()

	start := time.Now()
	for i := 0; i < packets; i++ {
		data := make([]byte, packetSize)
		data[0] = byte(i)
		conn.Write(data)
	}
	elapsed := time.Since(start)

	select {
	case count := <-done:
		pps := float64(count) / elapsed.Seconds()
		t.Logf("✅ Game traffic: %d/%d packets in %v (%.0f pps)", count, packets, elapsed, pps)
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout")
	}
}
