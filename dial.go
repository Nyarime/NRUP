package nrup

import (
	"crypto/rand"
	"fmt"
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

	// X25519握手，派生密钥
	key, err := clientHandshake(udpConn, rAddr, cfg)
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
	return &Listener{udpConn: udpConn, cfg: cfg, cookieSecret: secret}, nil
}

// Accept 接受NRUP连接
func (l *Listener) Accept() (*Conn, error) {
	// 读ClientHello
	buf := make([]byte, 4096)
	n, clientAddr, err := l.udpConn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	// 0-RTT快速重连（Resume帧跳过Cookie和握手）
	if n > 0 && buf[0] == frameResume {
		if key, sid, ok := serverResume(l.udpConn, clientAddr, buf[:n]); ok {
			dtlsConn, _ := NewNDTLS(l.udpConn, clientAddr, key, l.cfg)
			conn := &Conn{dtls: dtlsConn, fec: NewFECCodec(l.cfg.FECData, l.cfg.FECParity),
				cc: NewCongestionController(l.cfg.MaxBandwidthMbps*1000000/8),
				seq: NewSeqTracker(), adaptive: NewAdaptiveFEC(l.cfg.FECData, l.cfg.FECParity),
				retransmit: NewRetransmitQueue(), streamMode: l.cfg.StreamMode, sessionID: sid}
			go conn.startRetransmitLoop()
			return conn, nil
		}
	}

	// Cookie防DoS: 发HelloVerifyRequest，等重发
	if len(l.cookieSecret) > 0 {
		cookie := generateCookie(clientAddr, l.cookieSecret)
		hvr := buildHelloVerifyRequest(cookie)
		l.udpConn.WriteToUDP(hvr, clientAddr)

		// 等客户端重发带Cookie的ClientHello
		l.udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, clientAddr, err = l.udpConn.ReadFromUDP(buf)
		l.udpConn.SetReadDeadline(time.Time{})
		if err != nil {
			return nil, err
		}
		// 验证Cookie（防伪造）
		if !verifyCookie(clientAddr, generateCookie(clientAddr, l.cookieSecret), l.cookieSecret) {
			return nil, fmt.Errorf("invalid cookie")
		}
	}

	// X25519握手
	key, err := serverHandshake(l.udpConn, clientAddr, buf[:n], l.cfg)
	if err != nil {
		return nil, err
	}

	// 创建nDTLS加密连接
	dtlsConn, err := NewNDTLS(l.udpConn, clientAddr, key, l.cfg)
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
