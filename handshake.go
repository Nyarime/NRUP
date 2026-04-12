package nrup

import (
	"crypto/rand"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

const handshakeTimeout = 5 * time.Second

// AnyConnect-compatible DTLS cipher suites
var anyconnectCipherSuites = []byte{
	0xC0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0xC0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0x00, 0x3D, // TLS_RSA_WITH_AES_256_CBC_SHA256
	0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x00, 0x3C, // TLS_RSA_WITH_AES_128_CBC_SHA256
	0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x00, 0x0A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x00, 0xFF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
}

// clientHandshake X25519密钥交换，AnyConnect兼容DTLS握手
func clientHandshake(conn *net.UDPConn, serverAddr *net.UDPAddr, cfg *Config) ([]byte, error) {
	// 生成X25519密钥对
	var clientPrivate, clientPublic [32]byte
	if _, err := rand.Read(clientPrivate[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&clientPublic, &clientPrivate)

	// ClientHello
	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)
	var hello []byte
	if cfg.Disguise == "quic" {
		hello = buildQUICInitial(clientRandom, clientPublic[:], true, cfg.DisguiseSNI)
	} else {
		hello = buildAnyConnectClientHello(clientRandom, clientPublic[:])
	}
	conn.WriteToUDP(hello, serverAddr)

	// 读响应（可能是HelloVerifyRequest或ServerHello）
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("handshake timeout: %w", err)
	}

	// 检查是否是HelloVerifyRequest（handshake type 0x03）
	if n > 13 && buf[0] == 22 && buf[13] == 0x03 {
		// 收到Cookie挑战，重发ClientHello（重试3次，指数退避）
		var serverErr error
		for retry := 0; retry < 3; retry++ {
			conn.WriteToUDP(hello, serverAddr)
			timeout := 500 * time.Millisecond * time.Duration(1<<retry)
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, _, serverErr = conn.ReadFromUDP(buf)
			if serverErr == nil {
				break
			}
		}
		if serverErr != nil {
			return nil, fmt.Errorf("handshake timeout after cookie: %w", serverErr)
		}
	}

	var serverRandom, serverPublic []byte
	var err2 error
	if cfg.Disguise == "quic" {
		serverRandom, serverPublic, err2 = parseQUICInitial(buf[:n])
	} else {
		serverRandom, serverPublic, err2 = parseServerHello(buf[:n])
	}
	if err2 != nil {
		return nil, err2
	}

	// 跳过Certificate消息（AnyConnect模式且服务端配了证书时会发）
	if cfg.Disguise != "quic" {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if cn, _, cerr := conn.ReadFromUDP(buf); cerr == nil && cn > 13 && buf[0] == 22 && cn > 25 && buf[13] == 11 {
			// Certificate消息，忽略
		}
		conn.SetReadDeadline(time.Time{})
	}

	// X25519共享密钥
	var sharedSecret, serverPub [32]byte
	copy(serverPub[:], serverPublic)
	curve25519.ScalarMult(&sharedSecret, &clientPrivate, &serverPub)

	key := deriveSessionKey(sharedSecret[:], clientRandom, serverRandom)

	// TODO: Ed25519在demux模式下需要通过虚拟连接收发签名
	// Ed25519签名认证
	if cfg.AuthMode == "ed25519" && len(cfg.PrivateKey) > 0 && len(cfg.PeerPublicKey) > 0 {
		sig := signHandshake(cfg.PrivateKey, sharedSecret[:], clientRandom, serverRandom)
		conn.WriteToUDP(sig, serverAddr)
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		sigBuf := make([]byte, 128)
		sn, _, _ := conn.ReadFromUDP(sigBuf)
		if !verifyHandshakeSignature(cfg.PeerPublicKey, sigBuf[:sn], sharedSecret[:], serverRandom, clientRandom) {
			return nil, fmt.Errorf("ed25519 verify failed")
		}
		conn.SetReadDeadline(time.Time{})
	}

		// PSK认证（防MITM）
	if len(cfg.PSK) > 0 {
		// 发送客户端认证
		clientMAC := verifyPSK(cfg.PSK, sharedSecret[:], clientRandom, serverRandom)
		conn.WriteToUDP(clientMAC, serverAddr)
		// 接收服务端认证
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		macBuf := make([]byte, 32)
		n, _, err := conn.ReadFromUDP(macBuf)
		if err != nil || n != 32 {
			return nil, fmt.Errorf("PSK auth failed")
		}
		expected := verifyPSK(cfg.PSK, sharedSecret[:], serverRandom, clientRandom)
		if !hmac.Equal(macBuf[:n], expected) {
			return nil, fmt.Errorf("PSK mismatch") // 静默丢弃，不回复对端
		}
	}

	conn.SetReadDeadline(time.Time{})
	return key, nil
}

// serverHandshake 服务端握手
func serverHandshake(conn *net.UDPConn, clientAddr *net.UDPAddr, firstPacket []byte, cfg *Config) ([]byte, error) {
	var clientRandom, clientPublic []byte
	var err error
	if cfg.Disguise == "quic" {
		clientRandom, clientPublic, err = parseQUICInitial(firstPacket)
	} else {
		clientRandom, clientPublic, err = parseClientHello(firstPacket)
	}
	if err != nil {
		return nil, err
	}

	var serverPrivate, serverPublic [32]byte
	if _, err := rand.Read(serverPrivate[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&serverPublic, &serverPrivate)

	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	var hello []byte
	if cfg.Disguise == "quic" {
		hello = buildQUICInitial(serverRandom, serverPublic[:], false, cfg.DisguiseSNI)
	} else {
		hello = buildAnyConnectServerHello(serverRandom, serverPublic[:])
	}
	conn.WriteToUDP(hello, clientAddr)

	// 发送Certificate消息（AnyConnect模式发送，QUIC模式跳过）
	if cfg.Disguise != "quic" && len(cfg.CertDER) > 0 {
		certMsg := buildDTLSCertificate(cfg.CertDER)
		conn.WriteToUDP(certMsg, clientAddr)
	}

	var sharedSecret, clientPub [32]byte
	copy(clientPub[:], clientPublic)
	curve25519.ScalarMult(&sharedSecret, &serverPrivate, &clientPub)

	key := deriveSessionKey(sharedSecret[:], clientRandom, serverRandom)

	// TODO: Ed25519在demux模式下需要通过虚拟连接收发签名
	// Ed25519签名认证
	if cfg.AuthMode == "ed25519" && len(cfg.PrivateKey) > 0 && len(cfg.PeerPublicKey) > 0 {
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		sigBuf := make([]byte, 128)
		sn, _, _ := conn.ReadFromUDP(sigBuf)
		if !verifyHandshakeSignature(cfg.PeerPublicKey, sigBuf[:sn], sharedSecret[:], clientRandom, serverRandom) {
			return nil, fmt.Errorf("ed25519 verify failed")
		}
		sig := signHandshake(cfg.PrivateKey, sharedSecret[:], serverRandom, clientRandom)
		conn.WriteToUDP(sig, clientAddr)
		conn.SetReadDeadline(time.Time{})
	}

	// PSK认证（防MITM）
	if len(cfg.PSK) > 0 {
		// 接收客户端认证
		macBuf := make([]byte, 32)
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		n, _, err := conn.ReadFromUDP(macBuf)
		if err != nil || n != 32 {
			return nil, fmt.Errorf("auth timeout") // 静默丢弃
		}
		expected := verifyPSK(cfg.PSK, sharedSecret[:], clientRandom, serverRandom)
		if !hmac.Equal(macBuf[:n], expected) {
			return nil, fmt.Errorf("PSK mismatch") // 静默丢弃，不回复对端
		}
		// 发送服务端认证
		serverMAC := verifyPSK(cfg.PSK, sharedSecret[:], serverRandom, clientRandom)
		conn.WriteToUDP(serverMAC, clientAddr)
		conn.SetReadDeadline(time.Time{})
	}

	return key, nil
}

func deriveSessionKey(sharedSecret, clientRandom, serverRandom []byte) []byte {
	// HKDF-Extract + Expand (RFC 5869)
	salt := append(clientRandom, serverRandom...)
	info := []byte("nrup-session-key-v1")
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, 32)
	io.ReadFull(hkdfReader, key)
	return key
}

// === AnyConnect DTLS格式 ===

// buildAnyConnectClientHello 构造Cisco AnyConnect风格的DTLS ClientHello
func buildAnyConnectClientHello(random, pubkey []byte) []byte {
	// DTLS Record Layer
	// ContentType: Handshake (22)
	// Version: DTLS 1.0 (0xFEFF) - AnyConnect初始用1.0
	// Epoch: 0, SeqNum: 0

	// Handshake: ClientHello
	// Version: DTLS 1.2 (0xFEFD)
	// Random: 32 bytes (嵌入X25519 pubkey在session_id里)
	// Session ID: 32 bytes (放pubkey)
	// Cookie: 0
	// Cipher Suites: AnyConnect标准套件
	// Compression: null
	
	sessionID := pubkey[:32]

	// ClientHello body
	body := make([]byte, 0, 256)
	// client_version: DTLS 1.2
	body = append(body, 0xFE, 0xFD)
	// random (32 bytes)
	body = append(body, random...)
	// session_id (length + data) — 藏pubkey
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	// cookie (length + data)
	body = append(body, 0x00) // no cookie
	// cipher_suites
	body = append(body, byte(len(anyconnectCipherSuites)>>8), byte(len(anyconnectCipherSuites)))
	body = append(body, anyconnectCipherSuites...)
	// compression_methods
	body = append(body, 0x01, 0x00) // null compression

	// Handshake header
	handshake := make([]byte, 12)
	handshake[0] = 0x01 // ClientHello
	// length (3 bytes)
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	// message_seq
	binary.BigEndian.PutUint16(handshake[4:6], 0)
	// fragment_offset (3 bytes)
	handshake[6] = 0; handshake[7] = 0; handshake[8] = 0
	// fragment_length (3 bytes)
	handshake[9] = handshake[1]; handshake[10] = handshake[2]; handshake[11] = handshake[3]

	payload := append(handshake, body...)

	// DTLS Record header
	record := make([]byte, 13+len(payload))
	record[0] = 22 // Handshake
	record[1] = 0xFE; record[2] = 0xFF // DTLS 1.0
	// epoch (2) + seqnum (6)
	record[3] = 0; record[4] = 0
	record[5] = 0; record[6] = 0; record[7] = 0; record[8] = 0; record[9] = 0; record[10] = 0
	binary.BigEndian.PutUint16(record[11:13], uint16(len(payload)))
	copy(record[13:], payload)

	return record
}

// buildAnyConnectServerHello 构造ServerHello
func buildAnyConnectServerHello(random, pubkey []byte) []byte {
	sessionID := pubkey[:32]

	body := make([]byte, 0, 128)
	// server_version: DTLS 1.2
	body = append(body, 0xFE, 0xFD)
	// random
	body = append(body, random...)
	// session_id — 藏pubkey
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	// selected cipher suite: ECDHE_RSA_WITH_AES_256_CBC_SHA
	body = append(body, 0xC0, 0x14)
	// compression: null
	body = append(body, 0x00)

	handshake := make([]byte, 12)
	handshake[0] = 0x02 // ServerHello
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	binary.BigEndian.PutUint16(handshake[4:6], 0)
	handshake[6] = 0; handshake[7] = 0; handshake[8] = 0
	handshake[9] = handshake[1]; handshake[10] = handshake[2]; handshake[11] = handshake[3]

	payload := append(handshake, body...)

	record := make([]byte, 13+len(payload))
	record[0] = 22
	record[1] = 0xFE; record[2] = 0xFD // DTLS 1.2
	record[3] = 0; record[4] = 0
	record[5] = 0; record[6] = 0; record[7] = 0; record[8] = 0; record[9] = 0; record[10] = 1
	binary.BigEndian.PutUint16(record[11:13], uint16(len(payload)))
	copy(record[13:], payload)

	return record
}

func parseClientHello(pkt []byte) (random, pubkey []byte, err error) {
	if len(pkt) < 13 || pkt[0] != 22 {
		return nil, nil, errors.New("not a DTLS handshake")
	}
	// 验证DTLS版本 (0xFEFF=1.0 或 0xFEFD=1.2)
	if pkt[1] != 0xFE || (pkt[2] != 0xFF && pkt[2] != 0xFD) {
		return nil, nil, errors.New("invalid DTLS version")
	}
	// Skip record header (13) + handshake header (12) + version (2)
	offset := 13 + 12 + 2
	if len(pkt) < offset+32+1 {
		return nil, nil, errors.New("ClientHello too short")
	}
	random = pkt[offset : offset+32]
	offset += 32
	sidLen := int(pkt[offset])
	offset++
	if len(pkt) < offset+sidLen {
		return nil, nil, errors.New("session_id too short")
	}
	pubkey = pkt[offset : offset+sidLen]
	return random, pubkey, nil
}

func parseServerHello(pkt []byte) (random, pubkey []byte, err error) {
	if len(pkt) < 13 || pkt[0] != 22 {
		return nil, nil, errors.New("not a DTLS handshake")
	}
	offset := 13 + 12 + 2
	if len(pkt) < offset+32+1 {
		return nil, nil, errors.New("ServerHello too short")
	}
	random = pkt[offset : offset+32]
	offset += 32
	sidLen := int(pkt[offset])
	offset++
	if len(pkt) < offset+sidLen {
		return nil, nil, errors.New("session_id too short")
	}
	pubkey = pkt[offset : offset+sidLen]
	return random, pubkey, nil
}

// verifyPSK 用PSK验证握手（防MITM）
func verifyPSK(psk, sharedSecret, clientRandom, serverRandom []byte) []byte {
	if len(psk) == 0 { return nil }
	mac := hmac.New(sha256.New, psk)
	mac.Write(sharedSecret)
	mac.Write(clientRandom)
	mac.Write(serverRandom)
	return mac.Sum(nil)
}

// generateCookie 生成DTLS Cookie（防DoS洪泛）
func generateCookie(clientAddr *net.UDPAddr, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(clientAddr.String()))
	return mac.Sum(nil)[:20] // 20字节Cookie
}

// verifyCookie 验证Cookie
func verifyCookie(clientAddr *net.UDPAddr, cookie, secret []byte) bool {
	expected := generateCookie(clientAddr, secret)
	return hmac.Equal(cookie, expected)
}

// buildHelloVerifyRequest 构造DTLS HelloVerifyRequest
func buildHelloVerifyRequest(cookie []byte) []byte {
	// Handshake body: version(2) + cookie_length(1) + cookie
	body := make([]byte, 3+len(cookie))
	body[0] = 0xFE; body[1] = 0xFD // DTLS 1.2
	body[2] = byte(len(cookie))
	copy(body[3:], cookie)

	// Handshake header
	handshake := make([]byte, 12+len(body))
	handshake[0] = 0x03 // HelloVerifyRequest
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	binary.BigEndian.PutUint16(handshake[4:6], 0)
	handshake[9] = handshake[1]; handshake[10] = handshake[2]; handshake[11] = handshake[3]
	copy(handshake[12:], body)

	// DTLS Record
	record := make([]byte, 13+len(handshake))
	record[0] = 22 // Handshake
	record[1] = 0xFE; record[2] = 0xFF // DTLS 1.0
	binary.BigEndian.PutUint16(record[11:13], uint16(len(handshake)))
	copy(record[13:], handshake)

	return record
}

// signHandshake Ed25519签名
func signHandshake(privKey, sharedSecret, clientRandom, serverRandom []byte) []byte {
	msg := append(append(append([]byte{}, sharedSecret...), clientRandom...), serverRandom...)
	return ed25519.Sign(privKey, msg)
}

func verifyHandshakeSignature(pubKey, sig, sharedSecret, clientRandom, serverRandom []byte) bool {
	msg := append(append(append([]byte{}, sharedSecret...), clientRandom...), serverRandom...)
	return ed25519.Verify(pubKey, msg, sig)
}

// buildDTLSCertificate 构造DTLS Certificate消息
// 格式完全模拟AnyConnect ASA设备的证书交换
func buildDTLSCertificate(certDER []byte) []byte {
	certLen := len(certDER)

	// Handshake body: certificates_length(3) + cert_length(3) + cert
	body := make([]byte, 0, 6+certLen)
	// certificates list length (3 bytes)
	totalLen := 3 + certLen
	body = append(body, byte(totalLen>>16), byte(totalLen>>8), byte(totalLen))
	// single certificate length (3 bytes)
	body = append(body, byte(certLen>>16), byte(certLen>>8), byte(certLen))
	// certificate DER data
	body = append(body, certDER...)

	// Handshake header: type(1) + length(3) + seq(2) + frag_offset(3) + frag_length(3)
	hsType := byte(11) // Certificate
	hsLen := len(body)
	hs := make([]byte, 0, 12+hsLen)
	hs = append(hs, hsType)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, 0, 1) // message_seq = 1 (ServerHello=0, Certificate=1)
	hs = append(hs, 0, 0, 0) // fragment_offset = 0
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen)) // fragment_length
	hs = append(hs, body...)

	// DTLS record header
	record := make([]byte, 0, 13+len(hs))
	record = append(record, 22) // ContentType: Handshake
	record = append(record, 0xFE, 0xFD) // DTLS 1.2
	record = append(record, 0, 0) // epoch
	record = append(record, 0, 0, 0, 0, 0, 2) // sequence_number = 2
	record = append(record, byte(len(hs)>>8), byte(len(hs))) // length
	record = append(record, hs...)

	return record
}
