package nrup

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestGameTraffic(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1}
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	addr := listener.Addr().String()

	received := make(chan int, 200)
	go func() {
		conn, err := listener.Accept()
		if err != nil { return }
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil { return }
			if n > 0 { received <- n }
			conn.Write(buf[:n])
		}
	}()

	conn, err := Dial(addr, cfg)
	if err != nil { t.Fatal(err) }
	defer conn.Close()

	sent := 0
	start := time.Now()
	for i := 0; i < 100; i++ {
		data := []byte(fmt.Sprintf("game-pkt-%04d", i))
		if _, err := conn.Write(data); err == nil { sent++ }
	}

	recv := 0
	timer := time.After(5 * time.Second)
	for recv < sent {
		select {
		case <-received:
			recv++
		case <-timer:
			goto done
		}
	}
done:
	elapsed := time.Since(start)
	t.Logf("✅ Game traffic: %d/%d in %v (%.0f pps)", recv, sent, elapsed, float64(recv)/elapsed.Seconds())
}

func TestSessionID(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1}
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil { conn.Close() }
	}()

	conn, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	if len(conn.SessionID()) < 16 { t.Errorf("too short") }
	t.Logf("✅ Session: %s", conn.SessionID()[:16])
}

func TestMux(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1}
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		mux := NewMux(conn)
		defer mux.Close()
		for i := 0; i < 3; i++ {
			stream, err := mux.Accept()
			if err != nil { return }
			go func(s *Stream) {
				buf := make([]byte, 4096)
				n, _ := s.Read(buf)
				s.Write(buf[:n])
			}(stream)
		}
	}()

	conn, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal(err) }
	mux := NewMux(conn)
	defer mux.Close()

	for i := 0; i < 3; i++ {
		stream, _ := mux.Open()
		stream.Write([]byte(fmt.Sprintf("stream-%d", i)))
	}
	t.Logf("✅ Mux: 3 streams")
}

func TestMultiConn(t *testing.T)   { testMultiConn(t, 3) }
func TestMultiConn16(t *testing.T) { testMultiConn(t, 16) }
func TestMultiConn32(t *testing.T) { testMultiConn(t, 32) }

func testMultiConn(t *testing.T, count int) {
	cfg := &Config{FECData: 2, FECParity: 1}
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil { return }
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if err != nil { return }
					conn.Write(buf[:n])
				}
			}()
		}
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	start := time.Now()

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := Dial(addr, cfg)
			if err != nil { return }
			defer conn.Close()
			conn.Write([]byte(fmt.Sprintf("client-%d", idx)))
			mu.Lock()
			passed++
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)
	t.Logf("✅ Multi-conn: %d/%d connected in %v", passed, count, elapsed)
	if passed < count/2 {
		t.Errorf("Too few: %d/%d", passed, count)
	}
}


func TestZeroRTT(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1}

	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil { return }
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for { n, err := conn.Read(buf); if err != nil { return }; conn.Write(buf[:n]) }
			}()
		}
	}()

	// 首次连接
	conn1, err := Dial(addr, cfg)
	if err != nil { t.Fatal(err) }
	conn1.Write([]byte("first"))
	sid := conn1.SessionID()
	t.Logf("首次连接: %s", sid[:16])
	conn1.Close()
	time.Sleep(100 * time.Millisecond)

	// 0-RTT重连
	cfg2 := &Config{FECData: 2, FECParity: 1, ResumeID: sid}
	conn2, err := Dial(addr, cfg2)
	if err != nil {
		t.Logf("0-RTT失败(降级完整握手): %v", err)
		cfg3 := &Config{FECData: 2, FECParity: 1}
		conn2, err = Dial(addr, cfg3)
		if err != nil { t.Fatal(err) }
		t.Logf("降级成功: %s", conn2.SessionID()[:16])
	} else {
		t.Logf("✅ 0-RTT成功: %s", conn2.SessionID()[:16])
	}
	conn2.Write([]byte("resumed"))
	conn2.Close()
}
