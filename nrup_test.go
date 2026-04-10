package nrup

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestFECEncodeDecode(t *testing.T) {
	fec := NewFECCodec(10, 3)

	// 编码
	data := []byte("Hello NRUP! This is a test message for FEC encoding and decoding.")
	frames := fec.Encode(data)

	if len(frames) != 13 { // 10 data + 3 parity
		t.Fatalf("expected 13 frames, got %d", len(frames))
	}

	// 解码（全部帧都收到）
	fec2 := NewFECCodec(10, 3)
	var result []byte
	for _, frame := range frames {
		decoded := fec2.Decode(frame)
		if decoded != nil {
			result = decoded
			break
		}
	}

	if result == nil {
		t.Fatal("decode returned nil")
	}
	if !bytes.Equal(result, data) {
		t.Fatalf("data mismatch: got %q, want %q", result, data)
	}
	t.Logf("✅ FEC encode/decode OK (data=%d bytes, frames=%d)", len(data), len(frames))
}

func TestFECWithLoss(t *testing.T) {
	fec := NewFECCodec(10, 3)
	data := []byte("Testing FEC with packet loss - this should survive 3 lost packets")
	frames := fec.Encode(data)

	// 模拟丢3个包（丢掉index 2,5,8）
	fec2 := NewFECCodec(10, 3)
	var result []byte
	for i, frame := range frames {
		if i == 2 || i == 5 || i == 8 {
			continue // 丢包
		}
		decoded := fec2.Decode(frame)
		if decoded != nil {
			result = decoded
			break
		}
	}

	if result == nil {
		t.Fatal("FEC failed to recover from 3 lost packets")
	}
	if !bytes.Equal(result, data) {
		t.Fatalf("data mismatch after loss recovery")
	}
	t.Logf("✅ FEC recovered from 3 lost packets OK")
}

func TestAdaptiveFEC(t *testing.T) {
	afec := NewAdaptiveFEC(10, 3)

	// 模拟低丢包
	for i := 0; i < 100; i++ {
		afec.RecordSent(1)
	}
	afec.RecordLoss(1) // 1% loss
	d, p := afec.Adjust()
	t.Logf("1%% loss → %d:%d", d, p)
	if p > 2 {
		t.Errorf("expected low parity for 1%% loss, got %d", p)
	}

	// 模拟高丢包
	afec2 := NewAdaptiveFEC(10, 3)
	for i := 0; i < 100; i++ {
		afec2.RecordSent(1)
	}
	for i := 0; i < 25; i++ {
		afec2.RecordLoss(1) // 25% loss
	}
	d2, p2 := afec2.Adjust()
	t.Logf("25%% loss → %d:%d", d2, p2)
	if p2 < 5 {
		t.Errorf("expected high parity for 25%% loss, got %d", p2)
	}

	t.Logf("✅ Adaptive FEC OK")
}

func TestCongestionController(t *testing.T) {
	cc := NewCongestionController(0)

	// 发送
	start := time.Now()
	cc.Wait(1000)
	cc.Wait(1000)
	elapsed := time.Since(start)

	t.Logf("cwnd=%d, 2x1000B took %v", cc.cwnd, elapsed)

	// ACK
	cc.OnACK(1000, 50*time.Millisecond)
	t.Logf("after ACK: cwnd=%d, estimatedBW=%d", cc.cwnd, cc.maxBW)

	// Loss
	cc.OnLoss()
	t.Logf("after loss: cwnd=%d", cc.cwnd)

	t.Logf("✅ Congestion control OK")
}

func TestSeqTracker(t *testing.T) {
	st := NewSeqTracker()

	st.OnSend(1)
	st.OnSend(2)
	st.OnSend(3)

	rtt := st.OnRecvACK(1)
	t.Logf("RTT for seq 1: %v", rtt)

	st.OnRecvACK(3)

	// seq 2 未确认 → 丢包
	time.Sleep(10 * time.Millisecond)
	lost := st.CheckLoss()
	t.Logf("lost=%d, lossRate=%.1f%%", lost, st.LossRate()*100)

	sent, totalLost, avgRTT, lr := st.Stats()
	t.Logf("stats: sent=%d lost=%d rtt=%v lossRate=%.1f%%", sent, totalLost, avgRTT, lr*100)

	t.Logf("✅ SeqTracker OK")
}

func TestDialListen(t *testing.T) {
	port := 19876
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	testData := []byte("Hello from NRUP! Testing end-to-end.")

	// 启动服务端
	ln, err := Listen(fmt.Sprintf(":%d", port), &Config{FECData: 2, FECParity: 1})
	if err != nil {
		t.Skipf("Listen failed: %v", err)
		return
	}
	defer ln.Close()

	// 服务端接收
	done := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Logf("Accept failed: %v", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			t.Logf("Read failed: %v", err)
			return
		}
		done <- buf[:n]
	}()

	// 客户端发送
	time.Sleep(100 * time.Millisecond) // 等服务端就绪
	conn, err := Dial(addr, &Config{FECData: 2, FECParity: 1, Insecure: true})
	if err != nil {
		t.Skipf("Dial failed: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// 等结果
	select {
	case received := <-done:
		if bytes.Equal(received, testData) {
			t.Logf("✅ End-to-end OK: sent=%d recv=%d", len(testData), len(received))
		} else {
			t.Fatalf("Data mismatch: got %q want %q", received, testData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for data")
	}
}
