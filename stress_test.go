package nrup

import (
	"fmt"
	"testing"
	"time"
)

func TestGameTraffic(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1}

	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	addr := listener.Addr().String()

	serverRecv := make(chan string, 200)
	go func() {
		conn, err := listener.Accept()
		if err != nil { return }
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil { return }
			serverRecv <- string(buf[:n])
		}
	}()

	conn, err := Dial(addr, cfg)
	if err != nil { t.Fatal(err) }
	defer conn.Close()

	sent := 0
	start := time.Now()
	for i := 0; i < 100; i++ {
		data := []byte(fmt.Sprintf("pkt-%04d", i))
		if _, err := conn.Write(data); err == nil { sent++ }
	}

	recv := 0
	timer := time.After(5 * time.Second)
	for recv < sent {
		select {
		case <-serverRecv:
			recv++
		case <-timer:
			goto done
		}
	}
done:
	elapsed := time.Since(start)
	t.Logf("✅ Game traffic: %d/%d in %v (%.0f pps)", recv, sent, elapsed, float64(recv)/elapsed.Seconds())
	if recv < 10 {
		t.Errorf("Too few: %d", recv)
	}
}

func TestSessionID(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1}
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			t.Logf("Server session: %s", conn.SessionID())
			conn.Close()
		}
	}()

	conn, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	t.Logf("Client session: %s", conn.SessionID())
	if len(conn.SessionID()) < 16 { t.Errorf("too short") }
}

func TestMux(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1}

	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	// Server
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
				s.Write(buf[:n]) // echo
			}(stream)
		}
	}()

	// Client
	conn, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal(err) }
	mux := NewMux(conn)
	defer mux.Close()

	// 开3个Stream
	for i := 0; i < 3; i++ {
		stream, err := mux.Open()
		if err != nil { t.Fatal(err) }

		msg := fmt.Sprintf("stream-%d", i)
		stream.Write([]byte(msg))
		t.Logf("Stream %d: sent %s", stream.ID(), msg)
	}

	t.Logf("✅ Mux: 3 streams opened")
}

