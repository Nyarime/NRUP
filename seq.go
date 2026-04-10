package nrup

import (
	"sync"
	"time"
)

// SeqTracker 序列号跟踪+丢包检测
type SeqTracker struct {
	mu        sync.Mutex
	nextSeq   uint32
	ackMap    map[uint32]time.Time // seq → 发送时间
	received  map[uint32]bool      // 收到的seq
	rttSum    time.Duration
	rttCount  int
	lostCount int
	sentCount int
}

func NewSeqTracker() *SeqTracker {
	return &SeqTracker{
		ackMap:   make(map[uint32]time.Time),
		received: make(map[uint32]bool),
	}
}

// OnSend 记录发送
func (s *SeqTracker) OnSend(seq uint32) {
	s.mu.Lock()
	s.ackMap[seq] = time.Now()
	s.sentCount++
	s.mu.Unlock()
}

// OnRecvACK 收到确认
func (s *SeqTracker) OnRecvACK(seq uint32) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	sendTime, ok := s.ackMap[seq]
	if !ok {
		return 0
	}
	rtt := time.Since(sendTime)
	s.rttSum += rtt
	s.rttCount++
	delete(s.ackMap, seq)
	return rtt
}

// CheckLoss 检测丢包（超过2*RTT未确认=丢了）
func (s *SeqTracker) CheckLoss() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	avgRTT := s.AvgRTT()
	if avgRTT == 0 {
		avgRTT = 200 * time.Millisecond
	}
	timeout := avgRTT * 3

	lost := 0
	now := time.Now()
	for seq, sendTime := range s.ackMap {
		if now.Sub(sendTime) > timeout {
			delete(s.ackMap, seq)
			lost++
		}
	}
	s.lostCount += lost
	return lost
}

// AvgRTT 平均RTT
func (s *SeqTracker) AvgRTT() time.Duration {
	if s.rttCount == 0 {
		return 0
	}
	return s.rttSum / time.Duration(s.rttCount)
}

// LossRate 丢包率
func (s *SeqTracker) LossRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sentCount == 0 {
		return 0
	}
	return float64(s.lostCount) / float64(s.sentCount)
}

// Stats 统计
func (s *SeqTracker) Stats() (sent, lost int, rtt time.Duration, lossRate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sent = s.sentCount
	lost = s.lostCount
	rtt = s.AvgRTT()
	if sent > 0 {
		lossRate = float64(lost) / float64(sent)
	}
	return
}
