package nrup

import (
	"crypto/tls"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// Dial 连接NRUP服务端
func Dial(addr string, cfg *Config) (*Conn, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// DTLS连接
	dtlsConfig := &dtls.Config{
		InsecureSkipVerify: cfg.Insecure,
	}

	rAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	dtlsConn, err := dtls.Dial("udp", rAddr, dtlsConfig)
	if err != nil {
		return nil, err
	}

	return &Conn{
		dtls:     dtlsConn,
		fec:      NewFECCodec(cfg.FECData, cfg.FECParity),
		cc:       NewCongestionController(cfg.MaxBandwidth),
		seq:      NewSeqTracker(),
		adaptive:   NewAdaptiveFEC(cfg.FECData, cfg.FECParity),
		retransmit: NewRetransmitQueue(),
		streamMode: cfg.StreamMode,
	}, nil
}

// Listener NRUP服务端监听
type Listener struct {
	dtls net.Listener
	cfg  *Config
}

// Listen 创建NRUP监听
func Listen(addr string, cfg *Config) (*Listener, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	lAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	// 自签名证书（或加载）
	var certificate tls.Certificate
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		certificate, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
	} else {
		certificate, err = selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
	}

	dtlsConfig := &dtls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	dtlsListener, err := dtls.Listen("udp", lAddr, dtlsConfig)
	if err != nil {
		return nil, err
	}

	return &Listener{dtls: dtlsListener, cfg: cfg}, nil
}

// Accept 接受NRUP连接
func (l *Listener) Accept() (*Conn, error) {
	dtlsConn, err := l.dtls.Accept()
	if err != nil {
		return nil, err
	}

	return &Conn{
		dtls:     dtlsConn,
		fec:      NewFECCodec(l.cfg.FECData, l.cfg.FECParity),
		cc:       NewCongestionController(l.cfg.MaxBandwidth),
		seq:      NewSeqTracker(),
		adaptive:   NewAdaptiveFEC(l.cfg.FECData, l.cfg.FECParity),
		retransmit: NewRetransmitQueue(),
		streamMode: false,
	}, nil
}

// Close 关闭监听
func (l *Listener) Close() error {
	return l.dtls.Close()
}
