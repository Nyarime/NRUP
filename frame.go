package nrup

import (
	"encoding/binary"
)

// 帧类型
const (
	FrameData = 0x01 // 数据帧
	FrameACK  = 0x02 // 确认帧
	FramePing = 0x03 // 心跳帧
)

// DataFrame 数据帧
// [1B type=0x01][4B seq][1B fecIdx][1B fecTotal][2B dataLen][shard]
type DataFrame struct {
	Type     byte
	Seq      uint32
	FECIndex byte
	FECTotal byte
	DataLen  uint16
	Shard    []byte
}

func EncodeDataFrame(seq uint32, fecIdx, fecTotal byte, dataLen uint16, shard []byte) []byte {
	frame := make([]byte, 9+len(shard))
	frame[0] = FrameData
	binary.BigEndian.PutUint32(frame[1:5], seq)
	frame[5] = fecIdx
	frame[6] = fecTotal
	binary.BigEndian.PutUint16(frame[7:9], dataLen)
	copy(frame[9:], shard)
	return frame
}

func DecodeDataFrame(data []byte) *DataFrame {
	if len(data) < 9 || data[0] != FrameData {
		return nil
	}
	return &DataFrame{
		Type:     data[0],
		Seq:      binary.BigEndian.Uint32(data[1:5]),
		FECIndex: data[5],
		FECTotal: data[6],
		DataLen:  binary.BigEndian.Uint16(data[7:9]),
		Shard:    data[9:],
	}
}

// ACKFrame 确认帧
// [1B type=0x02][4B ackSeq][4B bitmap]
// bitmap: 32个seq的确认状态
type ACKFrame struct {
	Type    byte
	AckSeq  uint32
	Bitmap  uint32 // 从ackSeq开始，每bit=一个seq的确认状态
}

func EncodeACKFrame(ackSeq uint32, bitmap uint32) []byte {
	frame := make([]byte, 9)
	frame[0] = FrameACK
	binary.BigEndian.PutUint32(frame[1:5], ackSeq)
	binary.BigEndian.PutUint32(frame[5:9], bitmap)
	return frame
}

func DecodeACKFrame(data []byte) *ACKFrame {
	if len(data) < 9 || data[0] != FrameACK {
		return nil
	}
	return &ACKFrame{
		Type:   data[0],
		AckSeq: binary.BigEndian.Uint32(data[1:5]),
		Bitmap: binary.BigEndian.Uint32(data[5:9]),
	}
}

// PingFrame 心跳帧
// [1B type=0x03][8B timestamp]
type PingFrame struct {
	Type      byte
	Timestamp uint64
}

func EncodePingFrame(ts uint64) []byte {
	frame := make([]byte, 9)
	frame[0] = FramePing
	binary.BigEndian.PutUint64(frame[1:9], ts)
	return frame
}

func DecodePingFrame(data []byte) *PingFrame {
	if len(data) < 9 || data[0] != FramePing {
		return nil
	}
	return &PingFrame{
		Type:      data[0],
		Timestamp: binary.BigEndian.Uint64(data[1:9]),
	}
}
