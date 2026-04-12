package nrup

import (
	"sync"
	"time"
)

// OrderedBuffer 有序交付缓冲
// 乱序到达的包按序号排队，超时后强制交付
type OrderedBuffer struct {
	mu       sync.Mutex
	buffer   map[uint32][]byte
	nextSeq  uint32
	timeout  time.Duration
	lastRecv time.Time
}

func NewOrderedBuffer() *OrderedBuffer {
	return &OrderedBuffer{
		buffer:   make(map[uint32][]byte),
		timeout:  50 * time.Millisecond, // 50ms超时强制交付
		lastRecv: time.Now(),
	}
}

// Insert 插入数据，返回可以交付的有序数据
func (ob *OrderedBuffer) Insert(seq uint32, data []byte) [][]byte {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	ob.lastRecv = time.Now()
	ob.buffer[seq] = data

	// 尝试按序交付
	var result [][]byte
	for {
		d, ok := ob.buffer[ob.nextSeq]
		if !ok { break }
		result = append(result, d)
		delete(ob.buffer, ob.nextSeq)
		ob.nextSeq++
	}

	// 超时检查：如果有积压且等了太久，跳过缺失的包
	if len(ob.buffer) > 0 && len(result) == 0 {
		if time.Since(ob.lastRecv) > ob.timeout {
			// 找最小的积压序号，跳过缺失
			minSeq := uint32(0xFFFFFFFF)
			for s := range ob.buffer {
				if s < minSeq { minSeq = s }
			}
			// 跳到最小积压序号
			ob.nextSeq = minSeq
			for {
				d, ok := ob.buffer[ob.nextSeq]
				if !ok { break }
				result = append(result, d)
				delete(ob.buffer, ob.nextSeq)
				ob.nextSeq++
			}
		}
	}

	return result
}

// Pending 返回积压的包数
func (ob *OrderedBuffer) Pending() int {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	return len(ob.buffer)
}
