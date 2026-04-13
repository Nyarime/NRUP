package nrup

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
)

// FECCodec Reed-Solomon FEC
type FECCodec struct {
	mu           sync.Mutex
	dataShards   int
	parityShards int
	encoder      reedsolomon.Encoder
	seqNum       atomic.Uint32
	recvPool     map[uint32]*fecGroup
}

type fecGroup struct {
	shards   [][]byte
	present  []bool
	total    int
	dataLen  int
	received int
	created  time.Time
	decoded  bool // 已解码标记，防止重复返回
}

func NewFECCodec(data, parity int) *FECCodec {
	enc, _ := reedsolomon.New(data, parity)
	f := &FECCodec{
		dataShards:   data,
		parityShards: parity,
		encoder:      enc,
		recvPool:     make(map[uint32]*fecGroup),
	}
	go f.cleanupStaleGroups()
	return f
}

func (f *FECCodec) Encode(data []byte) [][]byte {
	seq := f.seqNum.Add(1)
	total := f.dataShards + f.parityShards
	shardSize := (len(data) + f.dataShards - 1) / f.dataShards

	shards := make([][]byte, total)
	for i := 0; i < f.dataShards; i++ {
		shards[i] = make([]byte, shardSize)
		start := i * shardSize
		end := start + shardSize
		if end > len(data) { end = len(data) }
		if start < len(data) { copy(shards[i], data[start:end]) }
	}
	for i := f.dataShards; i < total; i++ {
		shards[i] = make([]byte, shardSize)
	}

	f.encoder.Encode(shards)

	frames := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		frame := make([]byte, 8+len(shards[i]))
		binary.BigEndian.PutUint32(frame[0:4], seq)
		frame[4] = byte(i)
		frame[5] = byte(total)
		binary.BigEndian.PutUint16(frame[6:8], uint16(len(data)))
		copy(frame[8:], shards[i])
		frames = append(frames, frame)
	}
	return frames
}

func (f *FECCodec) Decode(frame []byte) []byte {
	if len(frame) < 9 { return nil }

	seq := binary.BigEndian.Uint32(frame[0:4])
	index := int(frame[4])
	total := int(frame[5])
	if total <= 0 || total > 255 || index >= total {
		return nil
	}
	if total > 64 { return nil } // 合理上限
	dataLen := int(binary.BigEndian.Uint16(frame[6:8]))
	shard := frame[8:]

	f.mu.Lock()
	defer f.mu.Unlock()

	group, exists := f.recvPool[seq]
	if !exists {
		group = &fecGroup{
			created: time.Now(),
			shards:  make([][]byte, total),
			present: make([]bool, total),
			total:   total,
			dataLen: dataLen,
		}
		f.recvPool[seq] = group
	}

	if index < group.total && index < total && !group.present[index] {
		group.shards[index] = make([]byte, len(shard))
		copy(group.shards[index], shard)
		group.present[index] = true
		group.received++
	}

	if group.received >= f.dataShards && !group.decoded {
		for i := 0; i < group.total; i++ {
			if !group.present[i] { group.shards[i] = nil }
		}
		err := f.encoder.Reconstruct(group.shards)
		if err == nil {
			group.decoded = true
			// 保留group不删除，防止重传帧创建新group重复解码
			result := make([]byte, 0, group.dataLen)
			for i := 0; i < f.dataShards; i++ {
				result = append(result, group.shards[i]...)
			}
			if len(result) > group.dataLen { result = result[:group.dataLen] }
			return result
		}
	}
	return nil
}

func (f *FECCodec) DecodeSingle(frame []byte) ([]byte, error) {
	if len(frame) < 8 { return nil, errors.New("frame too short") }
	dataLen := int(binary.BigEndian.Uint16(frame[6:8]))
	if len(frame) < 8+dataLen { return nil, errors.New("incomplete") }
	return frame[8 : 8+dataLen], nil
}

func (f *FECCodec) cleanupStaleGroups() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		f.mu.Lock()
		now := time.Now()
		for seq, g := range f.recvPool {
			if now.Sub(g.created) > 10*time.Second { delete(f.recvPool, seq) }

		}
		f.mu.Unlock()
	}
}

// FECStats FEC统计
type FECStats struct {
	GroupsReceived int
	GroupsRecovered int
	GroupsFailed int
}

// StreamEncoder 流式FEC编码（大包不等凑齐group）
type StreamEncoder struct {
	codec  *FECCodec
	buffer []byte
	mu     sync.Mutex
	maxBuf int
}

func NewStreamEncoder(dataShards, parityShards int) *StreamEncoder {
	return &StreamEncoder{
		codec:  NewFECCodec(dataShards, parityShards),
		buffer: make([]byte, 0, dataShards*1400),
		maxBuf: dataShards * 1400,
	}
}

// Write 接收数据，凑够一个group自动编码
func (s *StreamEncoder) Write(data []byte) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.buffer = append(s.buffer, data...)

	if len(s.buffer) >= s.maxBuf {
		chunk := s.buffer[:s.maxBuf]
		s.buffer = append([]byte{}, s.buffer[s.maxBuf:]...)
		return s.codec.Encode(chunk), nil
	}
	return nil, nil
}

// Flush 强制编码剩余数据
func (s *StreamEncoder) Flush() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.buffer) == 0 {
		return nil
	}
	frames := s.codec.Encode(s.buffer)
	s.buffer = s.buffer[:0]
	return frames
}
