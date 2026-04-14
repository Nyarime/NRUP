package nrup

import (
	"sync"
	"time"
)

// AdaptiveFEC 自适应FEC比例控制
// EWMA平滑 + FEC有效性反馈 + 连续丢包立即响应
type AdaptiveFEC struct {
	RTT time.Duration
	mu  sync.Mutex

	DataShards   int
	ParityShards int
	MinParity    int // 默认1
	MaxParity    int // 默认10

	// 滑动窗口
	window [100]bool
	winIdx int
	sent   int64
	lost   int64

	// EWMA平滑(v1.4.2: 防震荡)
	ewmaEff      float64 // EWMA平滑后的FEC有效性
	ewmaAlpha    float64 // EWMA系数(默认0.3)

	// 连续丢包检测(v1.4.2: 立即响应)
	consecutiveLoss int
	lastParity      int // 上次parity值(检测变化)

	fecCodec *FECCodec
}

func NewAdaptiveFEC(data, parity int) *AdaptiveFEC {
	return &AdaptiveFEC{
		DataShards:   data,
		ParityShards: parity,
		MinParity:    1,
		MaxParity:    10,
		ewmaAlpha:    0.3,
		lastParity:   parity,
	}
}

// RecordSent 记录发送
func (a *AdaptiveFEC) RecordSent(n int) {
	a.window[a.winIdx%100] = false
	a.mu.Lock()
	a.sent += int64(n)
	a.consecutiveLoss = 0 // 发送成功重置
	a.mu.Unlock()
}

// RecordLoss 记录丢包 + 连续丢包检测
func (a *AdaptiveFEC) RecordLoss(n int) {
	a.window[a.winIdx%100] = true
	a.winIdx++
	a.mu.Lock()
	a.lost += int64(n)
	a.consecutiveLoss += n

	// v1.4.2: 连续>=5个包丢失 → 立即提升FEC(不等30包周期)
	if a.consecutiveLoss >= 5 {
		boost := a.consecutiveLoss / 5 // 每5个连续丢包+1 parity
		if boost > 3 { boost = 3 }     // 最多+3
		newParity := a.ParityShards + boost
		if newParity > a.MaxParity { newParity = a.MaxParity }
		if newParity > a.ParityShards {
			a.ParityShards = newParity
		}
		a.consecutiveLoss = 0
	}
	a.mu.Unlock()
}

// Adjust 滑动窗口调整FEC比例 (EWMA平滑版)
func (a *AdaptiveFEC) Adjust() (data, parity int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.sent < 20 {
		return a.DataShards, a.ParityShards
	}

	// 滑动窗口丢包率
	lostInWindow := 0
	windowSize := int(a.sent)
	if windowSize > 100 { windowSize = 100 }
	for i := 0; i < windowSize; i++ {
		if a.window[i] { lostInWindow++ }
	}
	lossRate := float64(lostInWindow) / float64(windowSize)

	// RTT因子
	rttFactor := 1.0
	if a.RTT > 100*time.Millisecond { rttFactor = 1.5 }
	if a.RTT > 300*time.Millisecond { rttFactor = 2.0 }

	// 基于丢包率计算目标parity
	var targetParity int
	switch {
	case lossRate < 0.01:
		targetParity = a.MinParity
	case lossRate < 0.05:
		targetParity = int(float64(3) * rttFactor)
	case lossRate < 0.10:
		targetParity = int(float64(5) * rttFactor)
	case lossRate < 0.20:
		targetParity = int(float64(7) * rttFactor)
	case lossRate < 0.30:
		targetParity = int(float64(9) * rttFactor)
	default:
		targetParity = a.MaxParity
	}

	// v1.4.2: EWMA平滑FEC有效性(防震荡)
	if a.fecCodec != nil {
		rawEff := a.fecCodec.FECEffectiveness()
		a.ewmaEff = a.ewmaEff*(1-a.ewmaAlpha) + rawEff*a.ewmaAlpha

		if a.ewmaEff > 0.8 && targetParity > a.MinParity+1 {
			targetParity-- // FEC频繁恢复 → 冗余够，微降
		} else if a.ewmaEff < 0.3 && lossRate > 0.05 {
			targetParity++ // FEC效果差 → 冗余不足，微升
		}
	}

	// 限幅
	if targetParity < a.MinParity { targetParity = a.MinParity }
	if targetParity > a.MaxParity { targetParity = a.MaxParity }

	// v1.4.2: 每次最多变化±2(防剧烈震荡)
	diff := targetParity - a.ParityShards
	if diff > 2 { diff = 2 }
	if diff < -2 { diff = -2 }
	a.ParityShards += diff
	a.lastParity = a.ParityShards

	// 重置统计
	a.sent = 0
	a.lost = 0

	return a.DataShards, a.ParityShards
}
