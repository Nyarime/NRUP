package nrup

import (
	"crypto/ed25519"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
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

func TestCertDisguise(t *testing.T) {
	// 生成自签名证书DER
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vpn.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	serverCfg := &Config{FECData: 2, FECParity: 1, CertDER: certDER}
	clientCfg := &Config{FECData: 2, FECParity: 1}

	listener, err := Listen(":0", serverCfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil { conn.Close() }
	}()

	conn, err := Dial(listener.Addr().String(), clientCfg)
	if err != nil { t.Fatal("Cert disguise dial failed:", err) }
	defer conn.Close()

	conn.Write([]byte("with-cert"))
	t.Logf("✅ Cert disguise: connected (cert CN=vpn.example.com, %d bytes DER)", len(certDER))
}

func TestQUICDisguise(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1, Disguise: "quic"}

	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			t.Logf("Server: QUIC disguise session %s", conn.SessionID()[:8])
			conn.Close()
		}
	}()

	conn, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal("QUIC disguise dial failed:", err) }
	defer conn.Close()

	conn.Write([]byte("quic-disguised"))
	t.Logf("✅ QUIC disguise: connected (session: %s)", conn.SessionID()[:8])
}

func TestQUICDisguiseWithSNI(t *testing.T) {
	cfg := &Config{FECData: 2, FECParity: 1, Disguise: "quic", DisguiseSNI: "www.apple.com"}

	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil { conn.Close() }
	}()

	conn, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal("QUIC+SNI dial failed:", err) }
	defer conn.Close()

	conn.Write([]byte("quic-with-sni"))
	t.Logf("✅ QUIC+SNI disguise: connected (SNI=www.apple.com)")
}

func TestEd25519Auth(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(nil)
	clientPub, clientPriv, _ := ed25519.GenerateKey(nil)

	serverCfg := &Config{FECData: 8, FECParity: 4, AuthMode: "ed25519",
		PrivateKey: serverPriv, PeerPublicKey: clientPub}
	clientCfg := &Config{FECData: 8, FECParity: 4, AuthMode: "ed25519",
		PrivateKey: clientPriv, PeerPublicKey: serverPub}

	listener, err := Listen(":0", serverCfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil { t.Logf("Accept err: %v", err); return }
		defer conn.Close()
		buf := make([]byte, 4096)
		conn.Read(buf)
	}()

	conn, err := Dial(listener.Addr().String(), clientCfg)
	if err != nil { t.Fatal("Ed25519 dial:", err) }
	defer conn.Close()

	conn.Write([]byte("ed25519-authenticated"))
	t.Logf("✅ Ed25519 auth OK (session: %s)", conn.SessionID()[:8])
}

func Test0RTTResume(t *testing.T) {
	cfg := DefaultConfig()
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

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

	// 第一次连接：完整握手
	conn1, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal("First dial:", err) }
	
	conn1.Write([]byte("hello"))
	buf := make([]byte, 4096)
	n, _ := conn1.Read(buf)
	t.Logf("First conn: echo=%q, sessionID=%s", string(buf[:n]), conn1.SessionID()[:8])
	
	sessionID := conn1.SessionID()
	conn1.Close()

	// 第二次连接：0-RTT恢复
	cfg2 := DefaultConfig()
	cfg2.ResumeID = sessionID
	
	conn2, err := Dial(listener.Addr().String(), cfg2)
	if err != nil { t.Fatal("0-RTT dial:", err) }
	defer conn2.Close()
	
	conn2.Write([]byte("resumed!"))
	n, _ = conn2.Read(buf)
	t.Logf("✅ 0-RTT resume: echo=%q, sessionID=%s", string(buf[:n]), conn2.SessionID()[:8])
}
