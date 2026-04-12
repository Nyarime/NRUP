package nrup

import (
	"crypto/rand"
	"net"
	"time"
)

// Dial connects to an NRUP server at the given address.
// It performs X25519 key exchange disguised as AnyConnect DTLS handshake.
// Returns a Conn that implements FEC + ARQ reliable delivery.
func Dial(addr string, cfg *Config) (*Conn, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	rAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	// 0-RTT快速重连
	if cfg.ResumeID != "" {
		if key, ok := clientResume(udpConn, rAddr, cfg.ResumeID); ok {
			if dtls, err := NewNDTLS(udpConn, rAddr, key, cfg); err == nil {
				c := &Conn{dtls: dtls, fec: NewFECCodec(cfg.FECData, cfg.FECParity),
					cc: NewCongestionController(cfg.MaxBandwidthMbps*1000000/8),
					seq: NewSeqTracker(), adaptive: NewAdaptiveFEC(cfg.FECData, cfg.FECParity),
					retransmit: NewRetransmitQueue(), streamMode: cfg.StreamMode, sessionID: cfg.ResumeID}
				go c.startRetransmitLoop()
				return c, nil
			}
		}
	}

	// X25519握手（最多重试3次）
	var key []byte
	for attempt := 0; attempt < 3; attempt++ {
		key, err = clientHandshake(udpConn, rAddr, cfg)
		if err == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
		}
	}
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	// 创建nDTLS加密连接
	dtlsConn, err := NewNDTLS(udpConn, rAddr, key, cfg)
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	conn := &Conn{
		dtls:       dtlsConn,
		fec:        NewFECCodec(cfg.FECData, cfg.FECParity),
		cc:         NewCongestionController(cfg.MaxBandwidthMbps * 1000000 / 8),
		seq:        NewSeqTracker(),
		adaptive:   NewAdaptiveFEC(cfg.FECData, cfg.FECParity),
		retransmit: NewRetransmitQueue(),
		streamMode: cfg.StreamMode,
		sessionID:  generateSessionID(),
	}
	go conn.startRetransmitLoop()
	globalCache.Save(conn.sessionID, key, 24*time.Hour)
	return conn, nil
}

// Listener NRUP服务端监听
type Listener struct {
	demux        *udpDemux
	cookieSecret []byte
	udpConn *net.UDPConn
	cfg     *Config
}

// Listen creates an NRUP listener on the given address.
// Incoming connections are authenticated via X25519 handshake.
func Listen(addr string, cfg *Config) (*Listener, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	lAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 32)
	rand.Read(secret)
	dmx := newUDPDemux(udpConn)
	return &Listener{udpConn: udpConn, cfg: cfg, cookieSecret: secret, demux: dmx}, nil
}

// Accept 接受NRUP连接
func (l *Listener) Accept() (*Conn, error) {
	// 等待新连接（demux按源地址分发）
	dc, ok := <-l.demux.newConns
	if !ok {
		return nil, net.ErrClosed
	}

	buf := make([]byte, 4096)
	n, _, _ := dc.ReadFrom(buf)
	clientAddr := dc.remoteAddr

	// 0-RTT快速重连
	if n > 0 && buf[0] == frameResume {
		if key, sid, ok := serverResume(dc, clientAddr, buf[:n]); ok {
			dtlsConn, _ := NewNDTLS(dc, clientAddr, key, l.cfg)
			conn := &Conn{cfg: l.cfg, dtls: dtlsConn, fec: NewFECCodec(l.cfg.FECData, l.cfg.FECParity),
				cc: NewCongestionController(l.cfg.MaxBandwidthMbps*1000000/8),
				seq: NewSeqTracker(), adaptive: NewAdaptiveFEC(l.cfg.FECData, l.cfg.FECParity),
				retransmit: NewRetransmitQueue(), streamMode: l.cfg.StreamMode, sessionID: sid}
			go conn.startRetransmitLoop()
			return conn, nil
		}
	}

	// Cookie防DoS（重试3次，指数退避）
	if len(l.cookieSecret) > 0 {
		cookie := generateCookie(clientAddr, l.cookieSecret)
		hvr := buildHelloVerifyRequest(cookie)
		l.udpConn.WriteToUDP(hvr, clientAddr)
		var cookieErr error
		for retry := 0; retry < 5; retry++ {
			timeout := 300 * time.Millisecond * time.Duration(1<<retry)
			dc.SetReadDeadline(time.Now().Add(timeout))
			n2, _, err := dc.ReadFrom(buf)
			if err == nil {
				n = n2
				cookieErr = nil
				break
			}
			cookieErr = err
			// 重发HVR
			l.udpConn.WriteToUDP(hvr, clientAddr)
		}
		dc.SetReadDeadline(time.Time{})
		if cookieErr != nil { return nil, cookieErr }
	}

	// X25519握手
	key, err := serverHandshake(dc, clientAddr, buf[:n], l.cfg)
	if err != nil {
		return nil, err
	}

	// 创建nDTLS加密连接
	dtlsConn, err := NewNDTLS(dc, clientAddr, key, l.cfg)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		dtls:       dtlsConn,
		fec:        NewFECCodec(l.cfg.FECData, l.cfg.FECParity),
		cc:         NewCongestionController(l.cfg.MaxBandwidthMbps * 1000000 / 8),
		seq:        NewSeqTracker(),
		adaptive:   NewAdaptiveFEC(l.cfg.FECData, l.cfg.FECParity),
		retransmit: NewRetransmitQueue(),
		streamMode: l.cfg.StreamMode,
		sessionID:  generateSessionID(),
	}
	go conn.startRetransmitLoop()
	return conn, nil
}

// Addr 获取监听地址
func (l *Listener) Addr() net.Addr {
	return l.udpConn.LocalAddr()
}

// Close 关闭监听
func (l *Listener) Close() error {
	return l.udpConn.Close()
}
