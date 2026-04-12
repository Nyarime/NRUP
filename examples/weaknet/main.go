package main

import (
	"fmt"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/nyarime/nrup"
)

func main() {
	scenarios := []struct {
		name  string
		loss  string
		delay string
	}{
		{"正常网络", "0%", "0ms"},
		{"轻度 1%+50ms", "1%", "50ms"},
		{"中度 5%+100ms", "5%", "100ms"},
		{"重度 10%+100ms", "10%", "100ms"},
		{"极端 20%+200ms", "20%", "200ms"},
		{"恶劣 30%+200ms", "30%", "200ms"},
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  NRUP 弱网测试")
	fmt.Printf("  %-20s | %10s | %8s | %10s\n", "场景", "送达率", "平均延迟", "FEC恢复")
	fmt.Println("───────────────────────────────────────────────────────")

	for _, sc := range scenarios {
		exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
		if sc.loss != "0%" {
			exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem",
				"loss", sc.loss, "delay", sc.delay, "10ms").Run()
		}
		time.Sleep(50 * time.Millisecond)

		cfg := &nrup.Config{FECData: 10, FECParity: 3}
		sent, recv, latency := runTest(cfg, 30)

		fmt.Printf("  %-20s | %3d/%-3d %3.0f%% | %8s | %10s\n",
			sc.name, recv, sent, float64(recv)/float64(sent)*100,
			latency.Round(100*time.Microsecond),
			fecStatus(sent, recv))
	}

	exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
	fmt.Println("═══════════════════════════════════════════════════════")
}

func runTest(cfg *nrup.Config, count int) (sent, recv int, avgLat time.Duration) {
	listener, err := nrup.Listen(":0", cfg)
	if err != nil { return }
	defer listener.Close()

	var serverRecv atomic.Int64
	go func() {
		conn, err := listener.Accept()
		if err != nil { return }
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			_, err := conn.Read(buf)
			if err != nil { return }
			serverRecv.Add(1)
		}
	}()

	conn, err := nrup.Dial(listener.Addr().String(), cfg)
	if err != nil { return }
	defer conn.Close()

	start := time.Now()
	for i := 0; i < count; i++ {
		conn.Write([]byte(fmt.Sprintf("test-packet-%04d", i)))
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond) // 等FEC/ARQ恢复

	sent = count
	recv = int(serverRecv.Load())
	elapsed := time.Since(start)
	if recv > 0 {
		avgLat = elapsed / time.Duration(recv)
	}
	return
}

func fecStatus(sent, recv int) string {
	if recv >= sent { return "✅ 全恢复" }
	if recv >= sent*9/10 { return "✅ 良好" }
	if recv >= sent*7/10 { return "⚠️ 部分" }
	return "❌ 严重丢失"
}
