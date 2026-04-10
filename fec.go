package nrup

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
	"sync/atomic"

	"github.com/klauspost/reedsolomon"
)

// FECCodec Reed-Solomon前向纠错编解码器
type FECCodec struct {
	dataShards   int
	parityShards int
	encoder      reedsolomon.Encoder
	seqNum       atomic.Uint32

	// 接收端：缓存分片用于纠错
	mu       sync.Mutex
	recvPool map[uint32]*fecGroup
}

type fecGroup struct {
	shards   [][]byte
	present  []bool
	total    int
	dataLen  int
	created  time.Time // 超时清理用
}

// NewFECCodec 创建FEC编解码器
func NewFECCodec(data, parity int) *FECCodec {
	enc, _ := reedsolomon.New(data, parity)
	return &FECCodec{
		dataShards:   data,
		parityShards: parity,
		encoder:      enc,
		recvPool:     make(map[uint32]*fecGroup),
	}
}

// Encode FEC编码
// 输入: 原始数据
// 输出: 多个分片（data+parity），每个分片独立发送
func (f *FECCodec) Encode(data []byte) [][]byte {
	seq := f.seqNum.Add(1)
	total := f.dataShards + f.parityShards

	// 计算每个分片大小
	shardSize := (len(data) + f.dataShards - 1) / f.dataShards

	// 创建分片
	shards := make([][]byte, total)
	for i := 0; i < f.dataShards; i++ {
		shards[i] = make([]byte, shardSize)
		start := i * shardSize
		end := start + shardSize
		if end > len(data) {
			end = len(data)
		}
		if start < len(data) {
			copy(shards[i], data[start:end])
		}
	}
	for i := f.dataShards; i < total; i++ {
		shards[i] = make([]byte, shardSize)
	}

	// Reed-Solomon编码
	f.encoder.Encode(shards)

	// 封装成帧: [4B seq][1B index][1B total][2B dataLen][shard]
	frames := make([][]byte, total)
	for i := 0; i < total; i++ {
		frame := make([]byte, 8+len(shards[i]))
		binary.BigEndian.PutUint32(frame[0:4], seq)
		frame[4] = byte(i)
		frame[5] = byte(total)
		binary.BigEndian.PutUint16(frame[6:8], uint16(len(data)))
		copy(frame[8:], shards[i])
		frames[i] = frame
	}

	go f.cleanupStaleGroups()
	return frames
}

// Decode FEC解码
// 输入: 收到的单个帧
// 输出: 如果收集够了就返回原始数据，否则返回nil
func (f *FECCodec) Decode(frame []byte) []byte {
	if len(frame) < 8 {
		return nil
	}

	seq := binary.BigEndian.Uint32(frame[0:4])
	index := int(frame[4])
	total := int(frame[5])
	dataLen := int(binary.BigEndian.Uint16(frame[6:8]))
	shard := frame[8:]

	f.mu.Lock()
	defer f.mu.Unlock()

	// 获取或创建分组
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

	// 记录分片
	if index < total {
		group.shards[index] = make([]byte, len(shard)); copy(group.shards[index], shard)
		copy(group.shards[index], shard)
		group.present[index] = true
	}

	// 统计收到多少
	received := 0
	for _, p := range group.present {
		if p {
			received++
		}
	}

	// 收到>=dataShards个就可以恢复
	if received >= f.dataShards {
		// 标记缺失的分片为nil
		for i := 0; i < total; i++ {
			if !group.present[i] {
				group.shards[i] = nil
			}
		}

		// Reed-Solomon重建
		err := f.encoder.Reconstruct(group.shards)
		if err != nil {
			return nil
		}

		// 拼接数据分片
		result := make([]byte, 0, group.dataLen)
		for i := 0; i < f.dataShards; i++ {
			result = append(result, group.shards[i]...)
		}
		if len(result) > group.dataLen {
			result = result[:group.dataLen]
		}

		// 清理
		delete(f.recvPool, seq)

		return result
	}

	return nil
}

// DecodeSingle 单帧解码（无FEC，直接提取数据）
func (f *FECCodec) DecodeSingle(frame []byte) ([]byte, error) {
	if len(frame) < 8 {
		return nil, errors.New("frame too short")
	}
	dataLen := int(binary.BigEndian.Uint16(frame[6:8]))
	if len(frame) < 8+dataLen {
		return nil, errors.New("incomplete frame")
	}
	go f.cleanupStaleGroups()
	return frame[8 : 8+dataLen], nil
}

// cleanupStaleGroups 清理超时未完成的FEC组（防内存泄漏）
func (f *FECCodec) cleanupStaleGroups() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		f.mu.Lock()
		now := time.Now()
		for seq, group := range f.recvPool {
			if now.Sub(group.created) > 10*time.Second {
				delete(f.recvPool, seq)
			}
		}
		f.mu.Unlock()
	}
}
