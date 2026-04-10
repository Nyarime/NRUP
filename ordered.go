package nrup

import (
	"sync"
)

// OrderedBuffer 有序交付缓冲
// 确保数据按序列号顺序交付给应用层
type OrderedBuffer struct {
	mu       sync.Mutex
	buffer   map[uint32][]byte // seq → data
	nextSeq  uint32            // 期望的下一个seq
	ready    chan struct{}      // 通知有数据可读
}

func NewOrderedBuffer() *OrderedBuffer {
	return &OrderedBuffer{
		buffer:  make(map[uint32][]byte),
		nextSeq: 1,
		ready:   make(chan struct{}, 256),
	}
}

// Insert 插入收到的数据（可能乱序）
func (ob *OrderedBuffer) Insert(seq uint32, data []byte) {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	if seq < ob.nextSeq {
		return // 旧包，丢弃
	}

	ob.buffer[seq] = data

	// 检查是否有连续可交付的
	if seq == ob.nextSeq {
		select {
		case ob.ready <- struct{}{}:
		default:
		}
	}
}

// Read 有序读取（阻塞直到下一个seq可用）
func (ob *OrderedBuffer) Read() ([]byte, uint32) {
	for {
		ob.mu.Lock()
		data, ok := ob.buffer[ob.nextSeq]
		if ok {
			seq := ob.nextSeq
			delete(ob.buffer, seq)
			ob.nextSeq++
			ob.mu.Unlock()

			// 检查后续是否也就绪
			select {
			case ob.ready <- struct{}{}:
			default:
			}
			return data, seq
		}
		ob.mu.Unlock()

		// 等待新数据
		<-ob.ready
	}
}

// Pending 待交付的乱序包数量
func (ob *OrderedBuffer) Pending() int {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	return len(ob.buffer)
}
