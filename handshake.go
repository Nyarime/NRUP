package nrup

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"
)

// DTLS握手消息类型
const (
	handshakeClientHello  = 1
	handshakeServerHello  = 2
	handshakeFinished     = 20
)

// SimulateHandshake 模拟DTLS握手
// 让GFW看到完整的DTLS握手过程
func SimulateClientHandshake(conn net.PacketConn, remoteAddr net.Addr) error {
	// 发送 ClientHello
	hello := buildClientHello()
	record := wrapHandshakeRecord(hello, 0, 0)
	_, err := conn.WriteTo(record, remoteAddr)
	if err != nil {
		return err
	}

	// 等ServerHello
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadFrom(buf)
	conn.SetReadDeadline(time.Time{})
	return err
}

// SimulateServerHandshake 服务端响应握手
func SimulateServerHandshake(conn net.PacketConn) (net.Addr, error) {
	// 等ClientHello
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, clientAddr, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})

	// 发送 ServerHello + Finished
	hello := buildServerHello()
	record := wrapHandshakeRecord(hello, 0, 0)
	if _, err := conn.WriteTo(record, clientAddr); err != nil { return nil, err }

	return clientAddr, nil
}

// buildClientHello 构造DTLS ClientHello
func buildClientHello() []byte {
	// 简化的ClientHello，包含关键字段让GFW识别为真DTLS
	msg := make([]byte, 128)
	msg[0] = handshakeClientHello // HandshakeType
	// Length (3 bytes)
	msg[1] = 0; msg[2] = 0; msg[3] = 117
	// Message Sequence
	msg[4] = 0; msg[5] = 0
	// Fragment Offset (3 bytes)
	msg[6] = 0; msg[7] = 0; msg[8] = 0
	// Fragment Length (3 bytes)
	msg[9] = 0; msg[10] = 0; msg[11] = 117

	// ClientVersion = DTLS 1.2
	msg[12] = 0xFE; msg[13] = 0xFD

	// Random (32 bytes)
	rand.Read(msg[14:46])

	// Session ID Length = 0
	msg[46] = 0

	// Cookie Length = 0
	msg[47] = 0

	// Cipher Suites Length = 4 (2 suites)
	msg[48] = 0; msg[49] = 4
	// TLS_RSA_WITH_AES_256_GCM_SHA384
	msg[50] = 0x00; msg[51] = 0x9D
	// TLS_RSA_WITH_AES_128_GCM_SHA256
	msg[52] = 0x00; msg[53] = 0x9C

	// Compression Methods Length = 1
	msg[54] = 1
	msg[55] = 0 // null

	return msg[:56]
}

// buildServerHello 构造DTLS ServerHello
func buildServerHello() []byte {
	msg := make([]byte, 80)
	msg[0] = handshakeServerHello
	msg[1] = 0; msg[2] = 0; msg[3] = 70
	msg[4] = 0; msg[5] = 0
	msg[6] = 0; msg[7] = 0; msg[8] = 0
	msg[9] = 0; msg[10] = 0; msg[11] = 70

	// ServerVersion
	msg[12] = 0xFE; msg[13] = 0xFD

	// Random
	rand.Read(msg[14:46])

	// Session ID Length = 16
	msg[46] = 16
	rand.Read(msg[47:63])

	// Cipher Suite = AES_256_GCM
	msg[63] = 0x00; msg[64] = 0x9D

	// Compression = null
	msg[65] = 0

	return msg[:66]
}

// wrapHandshakeRecord 封装为DTLS记录
func wrapHandshakeRecord(payload []byte, epoch uint16, seq uint64) []byte {
	record := make([]byte, recordHeaderLen+len(payload))
	record[0] = contentHandshake // ContentType = 22
	binary.BigEndian.PutUint16(record[1:3], dtlsVersion)
	binary.BigEndian.PutUint16(record[3:5], epoch)
	record[5] = byte(seq >> 40)
	record[6] = byte(seq >> 32)
	record[7] = byte(seq >> 24)
	record[8] = byte(seq >> 16)
	record[9] = byte(seq >> 8)
	record[10] = byte(seq)
	binary.BigEndian.PutUint16(record[11:13], uint16(len(payload)))
	copy(record[recordHeaderLen:], payload)
	return record
}
