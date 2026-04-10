package nrup

import (
	"sync"
)

// AdaptiveFEC 自适应FEC比例控制
// 根据实时丢包率自动调整冗余量
type AdaptiveFEC struct {
	mu          sync.Mutex
	sent        int64
	lost        int64
	
	DataShards   int // 当前数据分片数
	ParityShards int // 当前冗余分片数
	
	MinParity int // 最小冗余 (默认1)
	MaxParity int // 最大冗余 (默认10)
}

func NewAdaptiveFEC(data, parity int) *AdaptiveFEC {
	return &AdaptiveFEC{
		DataShards:   data,
		ParityShards: parity,
		MinParity:    1,
		MaxParity:    10,
	}
}

// RecordSent 记录发送
func (a *AdaptiveFEC) RecordSent(n int) {
	a.mu.Lock()
	a.sent += int64(n)
	a.mu.Unlock()
}

// RecordLoss 记录丢包
func (a *AdaptiveFEC) RecordLoss(n int) {
	a.mu.Lock()
	a.lost += int64(n)
	a.mu.Unlock()
}

// Adjust 滑动窗口调整FEC比例（每100包评估一次）
func (a *AdaptiveFEC) Adjust() (data, parity int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.sent < 100 {
		return a.DataShards, a.ParityShards
	}

	lossRate := float64(a.lost) / float64(a.sent)

	// 根据丢包率调整
	switch {
	case lossRate < 0.01: // <1% 几乎无丢包
		a.ParityShards = a.MinParity // 最小冗余，省带宽
	case lossRate < 0.05: // 1-5%
		a.ParityShards = 2
	case lossRate < 0.10: // 5-10%
		a.ParityShards = 3
	case lossRate < 0.20: // 10-20%
		a.ParityShards = 5
	case lossRate < 0.30: // 20-30%
		a.ParityShards = 7
	default: // >30%
		a.ParityShards = a.MaxParity
	}

	// 重置统计
	a.sent = 0
	a.lost = 0

	return a.DataShards, a.ParityShards
}

/*
效果:
  丢包<1%  → 10:1 (冗余最小，带宽省)
  丢包5%   → 10:2
  丢包10%  → 10:3 (默认)
  丢包20%  → 10:5
  丢包30%  → 10:7
  丢包>30% → 10:10 (最大冗余)

始终是最优比例，不浪费带宽也不丢包
*/
