package nrup

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// BBR-style congestion controller
// 基于Google BBR论文的简化实现
// 核心思想: 用最大带宽和最小RTT估算最优发送速率

// CongestionController BBR拥塞控制器
type CongestionController struct {
	mu sync.Mutex

	// 估算值
	maxBW     int64         // 最大观测带宽 (bytes/s)
	minRTT    time.Duration // 最小观测RTT
	lastRTT   time.Duration

	// 状态
	bytesInFlight atomic.Int64
	delivered     int64 // 已确认的字节数
	deliveredTime time.Time

	// 窗口
	cwnd         int64 // 拥塞窗口 (bytes)
	pacingRate   int64 // 发送速率 (bytes/s)

	// BBR状态机
	state        bbrState
	cycleIdx     int
	probeRTTTime time.Time

	// 带宽采样
	bwSamples    [10]int64 // 最近10个带宽样本
	bwSampleIdx  int
	rttSamples   [10]time.Duration
	rttSampleIdx int

	// 限制
	maxBandwidth int64 // 用户设置的上限, 0=不限
}

type bbrState int

const (
	bbrStartup   bbrState = iota // 指数增长探测带宽
	bbrDrain                      // 排空队列
	bbrProbeBW                    // 稳态，周期性探测
	bbrProbeRTT                   // 探测最小RTT
)

const (
	startupGain = 2.89  // 2/ln(2)
	drainGain   = 0.35  // 1/startupGain
	steadyGain  = 1.0
	probeGains  = 1.25  // 探测时加25%

	initCwnd    = 32768  // 初始32KB
	minCwnd     = 4096   // 最小4KB
)

// NewCongestionController 创建BBR控制器
func NewCongestionController(maxBW int64) *CongestionController {
	cc := &CongestionController{
		maxBandwidth: maxBW,
		cwnd:         initCwnd,
		minRTT:       time.Duration(math.MaxInt64),
		state:        bbrStartup,
		deliveredTime: time.Now(),
	}
	return cc
}

// Wait 等待发送许可
func (cc *CongestionController) Wait(size int) {
	for cc.bytesInFlight.Load() > cc.cwnd {
		time.Sleep(time.Millisecond)
	}
	cc.bytesInFlight.Add(int64(size))

	// 按pacing rate限速
	if cc.pacingRate > 0 {
		delay := time.Duration(float64(size) / float64(cc.pacingRate) * float64(time.Second))
		if delay > 500*time.Microsecond {
			time.Sleep(delay)
		}
	}
}

// OnACK 收到确认
func (cc *CongestionController) OnACK(bytes int64, rtt time.Duration) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.bytesInFlight.Add(-bytes)
	cc.lastRTT = rtt

	if rtt > 0 {
		// 更新最小RTT
		if rtt < cc.minRTT {
			cc.minRTT = rtt
		}
		cc.rttSamples[cc.rttSampleIdx%10] = rtt
		cc.rttSampleIdx++

		// 计算带宽样本
		now := time.Now()
		elapsed := now.Sub(cc.deliveredTime)
		if elapsed > 0 {
			bw := bytes * int64(time.Second) / int64(elapsed)
			cc.bwSamples[cc.bwSampleIdx%10] = bw
			cc.bwSampleIdx++
			
			// 最大带宽 = 最近10个样本的最大值
			cc.maxBW = 0
			for _, s := range cc.bwSamples {
				if s > cc.maxBW {
					cc.maxBW = s
				}
			}
		}
		cc.delivered += bytes
		cc.deliveredTime = now
	}

	// BBR状态机
	cc.updateState()

	// 更新cwnd和pacing rate
	cc.updateCwnd()
}

// OnLoss 检测到丢包
func (cc *CongestionController) OnLoss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// BBR不像CUBIC那样大幅降窗
	// 只减少一点，避免排队
	cc.cwnd = cc.cwnd * 85 / 100 // 降15%（比TCP温和）
	if cc.cwnd < minCwnd {
		cc.cwnd = minCwnd
	}
}

func (cc *CongestionController) updateState() {
	switch cc.state {
	case bbrStartup:
		// 如果带宽不再增长，进入Drain
		if cc.bwSampleIdx >= 3 {
			recent := cc.bwSamples[(cc.bwSampleIdx-1)%10]
			prev := cc.bwSamples[(cc.bwSampleIdx-2)%10]
			if recent <= prev {
				cc.state = bbrDrain
			}
		}

	case bbrDrain:
		// 排空队列后进入ProbeBW
		if cc.bytesInFlight.Load() <= cc.bdp() {
			cc.state = bbrProbeBW
			cc.cycleIdx = 0
		}

	case bbrProbeBW:
		cc.cycleIdx++
		// 每10个RTT进行一次ProbeRTT
		if cc.cycleIdx >= 10 && time.Since(cc.probeRTTTime) > 10*time.Second {
			cc.state = bbrProbeRTT
			cc.probeRTTTime = time.Now()
		}

	case bbrProbeRTT:
		// 200ms后回到ProbeBW
		if time.Since(cc.probeRTTTime) > 200*time.Millisecond {
			cc.state = bbrProbeBW
			cc.cycleIdx = 0
		}
	}
}

func (cc *CongestionController) updateCwnd() {
	bdp := cc.bdp()

	var gain float64
	switch cc.state {
	case bbrStartup:
		gain = startupGain
	case bbrDrain:
		gain = drainGain
	case bbrProbeBW:
		// 周期性探测: 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
		gains := []float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}
		gain = gains[cc.cycleIdx%8]
	case bbrProbeRTT:
		gain = 0.5
	}

	cc.cwnd = int64(float64(bdp) * gain)
	if cc.cwnd < minCwnd {
		cc.cwnd = minCwnd
	}

	cc.pacingRate = int64(float64(cc.maxBW) * gain)

	// 用户限速
	if cc.maxBandwidth > 0 && cc.pacingRate > cc.maxBandwidth {
		cc.pacingRate = cc.maxBandwidth
	}
}

// bdp 带宽延迟积
func (cc *CongestionController) bdp() int64 {
	if cc.maxBW == 0 || cc.minRTT == time.Duration(math.MaxInt64) {
		return initCwnd
	}
	return cc.maxBW * int64(cc.minRTT) / int64(time.Second)
}

// GetState 获取当前状态（调试用）
func (cc *CongestionController) GetState() string {
	states := []string{"startup", "drain", "probe_bw", "probe_rtt"}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return states[cc.state]
}
