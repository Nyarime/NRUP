package nrup

import (
	"crypto/rand"
	"fmt"
)

// QUIC v1 常量
const (
	quicVersion1    = 0x00000001
	quicLongHeader  = 0xC0 // Initial packet
	quicShortHeader = 0x40 // 1-RTT packet
)

// buildQUICInitial 构造QUIC Initial包格式
// 把X25519公钥嵌入DCID/SCID字段
func buildQUICInitial(random, pubkey []byte, isClient bool, sni ...string) []byte {
	pkt := make([]byte, 0, 128+len(pubkey))

	// Header Form (1) + Fixed Bit (1) + Packet Type (2) + Reserved (2) + PN Length (2)
	if isClient {
		pkt = append(pkt, 0xC3) // Initial, PN length 4
	} else {
		pkt = append(pkt, 0xC3) // Same for server (Initial response)
	}

	// Version: QUIC v1
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x01)

	// DCID: 嵌入random前8字节
	dcidLen := 8
	pkt = append(pkt, byte(dcidLen))
	if len(random) >= dcidLen {
		pkt = append(pkt, random[:dcidLen]...)
	} else {
		buf := make([]byte, dcidLen)
		copy(buf, random)
		pkt = append(pkt, buf...)
	}

	// SCID: 嵌入random后8字节
	scidLen := 8
	pkt = append(pkt, byte(scidLen))
	if len(random) >= 16 {
		pkt = append(pkt, random[8:16]...)
	} else {
		buf := make([]byte, scidLen)
		rand.Read(buf)
		pkt = append(pkt, buf...)
	}

	// Token Length (variable-length int): 0 for server, 0 for client initial
	pkt = append(pkt, 0x00)

	// Payload: pubkey + random padding (嵌入X25519公钥)
	payload := make([]byte, 0, 64+len(pubkey))
	// Packet Number (4 bytes)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)
	// CRYPTO frame: 嵌入TLS ClientHello (含SNI extension)
	payload = append(payload, 0x06) // CRYPTO frame type
	payload = append(payload, 0x00) // offset = 0

	// 构建ClientHello数据
	chData := make([]byte, 0, 128)
	// random剩余部分
	if len(random) > 16 {
		chData = append(chData, random[16:]...)
	}
	// pubkey
	chData = append(chData, pubkey...)
	// SNI extension (type 0x0000)
	if len(sni) > 0 && sni[0] != "" {
		sniBytes := []byte(sni[0])
		// Extension: server_name (0x0000)
		chData = append(chData, 0x00, 0x00) // extension type
		sniListLen := 2 + 1 + 2 + len(sniBytes) // list_len + type + name_len + name
		chData = append(chData, byte(sniListLen>>8), byte(sniListLen)) // extension length
		chData = append(chData, byte((sniListLen-2)>>8), byte(sniListLen-2)) // server_name_list length
		chData = append(chData, 0x00) // host_name type
		chData = append(chData, byte(len(sniBytes)>>8), byte(len(sniBytes))) // name length
		chData = append(chData, sniBytes...) // hostname
	}

	dataLen := len(chData)
	payload = append(payload, byte(dataLen>>8), byte(dataLen))
	payload = append(payload, chData...)
	// Padding to minimum 1200 bytes? No - keep it small for UDP
	// 加一些随机padding让长度更自然
	padLen := 32
	pad := make([]byte, padLen)
	rand.Read(pad)
	payload = append(payload, pad...)

	// Length field (variable-length int, 2 bytes for values < 16383)
	payloadLen := len(payload)
	pkt = append(pkt, byte(0x40|byte(payloadLen>>8)), byte(payloadLen))

	pkt = append(pkt, payload...)
	return pkt
}

// parseQUICInitial 从QUIC Initial包中提取random和pubkey
func parseQUICInitial(pkt []byte) (random, pubkey []byte, err error) {
	if len(pkt) < 20 {
		return nil, nil, errNotDTLS
	}
	// 验证Header Form bit
	if pkt[0]&0x80 == 0 {
		return nil, nil, errNotDTLS
	}
	// 验证QUIC version
	if pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0 || pkt[4] != 1 {
		return nil, nil, errNotDTLS
	}

	offset := 5
	// DCID
	dcidLen := int(pkt[offset])
	offset++
	if len(pkt) < offset+dcidLen {
		return nil, nil, errNotDTLS
	}
	dcid := pkt[offset : offset+dcidLen]
	offset += dcidLen

	// SCID
	scidLen := int(pkt[offset])
	offset++
	if len(pkt) < offset+scidLen {
		return nil, nil, errNotDTLS
	}
	scid := pkt[offset : offset+scidLen]
	offset += scidLen

	// Token length
	tokenLen := int(pkt[offset])
	offset++
	offset += tokenLen

	// Length (2-byte variable-length int)
	if len(pkt) < offset+2 {
		return nil, nil, errNotDTLS
	}
	payloadLen := int(pkt[offset]&0x3F)<<8 | int(pkt[offset+1])
	offset += 2
	_ = payloadLen

	// Skip packet number (4 bytes)
	offset += 4

	// CRYPTO frame
	if len(pkt) < offset+4 {
		return nil, nil, errNotDTLS
	}
	offset++ // frame type
	offset++ // offset
	dataLen := int(pkt[offset])<<8 | int(pkt[offset+1])
	offset += 2

	// Reconstruct random from DCID + SCID + remaining
	random = make([]byte, 32)
	copy(random[:8], dcid)
	copy(random[8:16], scid)
	remaining := 32 - 16
	if len(pkt) >= offset+remaining {
		copy(random[16:], pkt[offset:offset+remaining])
		offset += remaining
	}

	// pubkey
	pubkeyLen := dataLen - remaining
	if pubkeyLen > 0 && len(pkt) >= offset+pubkeyLen {
		pubkey = pkt[offset : offset+pubkeyLen]
	}

	return random, pubkey, nil
}

var errNotDTLS = fmt.Errorf("not a valid packet")
