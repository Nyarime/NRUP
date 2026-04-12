package nrup

import (
	"crypto/rand"
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

// clientHandshake X25519密钥交换，伪装AnyConnect DTLS握手
func clientHandshake(conn *net.UDPConn, serverAddr *net.UDPAddr, cfg *Config) ([]byte, error) {
	// 生成X25519密钥对
	var clientPrivate, clientPublic [32]byte
	if _, err := rand.Read(clientPrivate[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&clientPublic, &clientPrivate)

	// ClientHello (AnyConnect风格)
	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)
	hello := buildAnyConnectClientHello(clientRandom, clientPublic[:])
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
		// 收到Cookie挑战，重发ClientHello
		conn.WriteToUDP(hello, serverAddr)
		// 等真正的ServerHello
		n, _, err = conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("handshake timeout after cookie: %w", err)
		}
	}

	serverRandom, serverPublic, err := parseServerHello(buf[:n])
	if err != nil {
		return nil, err
	}

	// X25519共享密钥
	var sharedSecret, serverPub [32]byte
	copy(serverPub[:], serverPublic)
	curve25519.ScalarMult(&sharedSecret, &clientPrivate, &serverPub)

	key := deriveSessionKey(sharedSecret[:], clientRandom, serverRandom)

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
			return nil, fmt.Errorf("PSK mismatch: MITM detected")
		}
	}

	conn.SetReadDeadline(time.Time{})
	return key, nil
}

// serverHandshake 服务端握手
func serverHandshake(conn *net.UDPConn, clientAddr *net.UDPAddr, firstPacket []byte, cfg *Config) ([]byte, error) {
	clientRandom, clientPublic, err := parseClientHello(firstPacket)
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
	hello := buildAnyConnectServerHello(serverRandom, serverPublic[:])
	conn.WriteToUDP(hello, clientAddr)

	var sharedSecret, clientPub [32]byte
	copy(clientPub[:], clientPublic)
	curve25519.ScalarMult(&sharedSecret, &serverPrivate, &clientPub)

	key := deriveSessionKey(sharedSecret[:], clientRandom, serverRandom)

	// PSK认证（防MITM）
	if len(cfg.PSK) > 0 {
		// 接收客户端认证
		macBuf := make([]byte, 32)
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		n, _, err := conn.ReadFromUDP(macBuf)
		if err != nil || n != 32 {
			return nil, fmt.Errorf("PSK auth timeout")
		}
		expected := verifyPSK(cfg.PSK, sharedSecret[:], clientRandom, serverRandom)
		if !hmac.Equal(macBuf[:n], expected) {
			return nil, fmt.Errorf("PSK mismatch: MITM detected")
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
