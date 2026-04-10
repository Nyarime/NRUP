package nrup

import (
	"sync"
	"time"
)

// RetransmitQueue 选择性重传队列
type RetransmitQueue struct {
	mu       sync.Mutex
	pending  map[uint32]*retransmitEntry
	maxRetry int
}

type retransmitEntry struct {
	frames   [][]byte  // 原始FEC帧
	sentAt   time.Time
	retries  int
	rto      time.Duration
}

func NewRetransmitQueue() *RetransmitQueue {
	return &RetransmitQueue{
		pending:  make(map[uint32]*retransmitEntry),
		maxRetry: 3,
	}
}

// Add 记录已发送的帧组（用于可能的重传）
func (rq *RetransmitQueue) Add(seq uint32, frames [][]byte, rto time.Duration) {
	rq.mu.Lock()
	rq.pending[seq] = &retransmitEntry{
		frames:  frames,
		sentAt:  time.Now(),
		rto:     rto,
	}
	rq.mu.Unlock()
}

// ACK 确认收到，从队列移除
func (rq *RetransmitQueue) ACK(seq uint32) {
	rq.mu.Lock()
	delete(rq.pending, seq)
	rq.mu.Unlock()
}

// GetExpired 获取需要重传的帧
func (rq *RetransmitQueue) GetExpired() []retransmitResult {
	rq.mu.Lock()
	defer rq.mu.Unlock()

	var results []retransmitResult
	now := time.Now()

	for seq, entry := range rq.pending {
		if now.Sub(entry.sentAt) > entry.rto {
			if entry.retries >= rq.maxRetry {
				// 超过最大重试，放弃
				delete(rq.pending, seq)
				continue
			}
			entry.retries++
			entry.sentAt = now
			results = append(results, retransmitResult{
				Seq:    seq,
				Frames: entry.frames,
			})
		}
	}
	return results
}

type retransmitResult struct {
	Seq    uint32
	Frames [][]byte
}

// Size 队列大小
func (rq *RetransmitQueue) Size() int {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	return len(rq.pending)
}
