package nrup

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// BBR congestion controller
// Based on Google BBR (Bottleneck Bandwidth and Round-trip propagation time)
// Reference: https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control

type CongestionController struct {
	mu sync.Mutex

	// Estimates
	maxBW     int64         // max observed bandwidth (bytes/s)
	minRTT    time.Duration // min observed RTT
	lastRTT   time.Duration
	rtt       time.Duration // smoothed RTT (exported for stats)

	// State
	bytesInFlight atomic.Int64
	delivered     int64
	deliveredTime time.Time

	// Window
	cwnd       int64 // congestion window (bytes)
	pacingRate int64 // send rate (bytes/s)

	// BBR state machine
	state          bbrState
	cycleIdx       int
	probeRTTStart  time.Time
	minRTTExpiry   time.Time // minRTT expires after 10s, triggers ProbeRTT
	probeRTTDone   bool
	priorCwnd      int64 // saved cwnd before ProbeRTT

	// Bandwidth samples (sliding window)
	bwSamples    [10]int64
	bwSampleIdx  int
	rttSamples   [10]time.Duration
	rttSampleIdx int

	// Limits
	maxBandwidth int64 // user-configured cap, 0=unlimited
}

type bbrState int

const (
	bbrStartup  bbrState = iota // exponential BW growth
	bbrDrain                     // drain inflight to BDP
	bbrProbeBW                   // steady state, cycle gains
	bbrProbeRTT                  // measure min RTT
)

const (
	startupGain    = 2.89  // 2/ln(2)
	drainGain      = 0.35  // 1/startupGain
	steadyGain     = 1.0
	probeRTTCwnd   = 4 * 1500 // 4 packets during ProbeRTT
	minRTTWindow   = 10 * time.Second
	probeRTTDuration = 200 * time.Millisecond

	initCwnd = 32768  // 32KB
	minCwnd  = 4096   // 4KB
)

func NewCongestionController(maxBW int64) *CongestionController {
	cc := &CongestionController{
		maxBandwidth:  maxBW,
		cwnd:          initCwnd,
		minRTT:        time.Duration(math.MaxInt64),
		state:         bbrStartup,
		deliveredTime: time.Now(),
		minRTTExpiry:  time.Now().Add(minRTTWindow),
	}
	return cc
}

// Wait for send permission (pacing + cwnd)
func (cc *CongestionController) Wait(size int) {
	for cc.bytesInFlight.Load() > cc.cwnd {
		time.Sleep(time.Millisecond)
	}
	cc.bytesInFlight.Add(int64(size))

	if cc.pacingRate > 0 {
		delay := time.Duration(float64(size) / float64(cc.pacingRate) * float64(time.Second))
		if delay > 500*time.Microsecond {
			time.Sleep(delay)
		}
	}
}

// OnACK processes acknowledgment
func (cc *CongestionController) OnACK(bytes int64, rtt time.Duration) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.bytesInFlight.Add(-bytes)
	cc.lastRTT = rtt

	if rtt > 0 {
		// Smoothed RTT (EWMA)
		if cc.rtt == 0 {
			cc.rtt = rtt
		} else {
			cc.rtt = cc.rtt*7/8 + rtt/8 // EWMA alpha=0.125 (RFC 6298)
		}

		// Update min RTT
		if rtt < cc.minRTT || time.Now().After(cc.minRTTExpiry) {
			cc.minRTT = rtt
			cc.minRTTExpiry = time.Now().Add(minRTTWindow)
		}

		cc.rttSamples[cc.rttSampleIdx%10] = rtt
		cc.rttSampleIdx++

		// Bandwidth sample
		now := time.Now()
		elapsed := now.Sub(cc.deliveredTime)
		if elapsed > 0 {
			bw := bytes * int64(time.Second) / int64(elapsed)
			cc.bwSamples[cc.bwSampleIdx%10] = bw
			cc.bwSampleIdx++

			// Max BW = max of recent samples
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

	cc.updateState()
	cc.updateCwnd()
}

// OnLoss handles packet loss
func (cc *CongestionController) OnLoss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// BBR: gentle reduction (not halving like CUBIC)
	cc.cwnd = cc.cwnd * 85 / 100
	if cc.cwnd < minCwnd {
		cc.cwnd = minCwnd
	}
}

func (cc *CongestionController) updateState() {
	switch cc.state {
	case bbrStartup:
		// Exit startup when BW plateaus
		if cc.bwSampleIdx >= 3 {
			recent := cc.bwSamples[(cc.bwSampleIdx-1)%10]
			prev := cc.bwSamples[(cc.bwSampleIdx-2)%10]
			// BW growth < 25% → startup done
			if prev > 0 && float64(recent)/float64(prev) < 1.25 {
				cc.state = bbrDrain
				cc.priorCwnd = cc.cwnd
			}
		}

	case bbrDrain:
		// Drain until inflight <= BDP
		if cc.bytesInFlight.Load() <= cc.bdp() {
			cc.state = bbrProbeBW
			cc.cycleIdx = 0
		}

	case bbrProbeBW:
		cc.cycleIdx++
		// Check if minRTT needs refresh
		if time.Now().After(cc.minRTTExpiry) {
			cc.state = bbrProbeRTT
			cc.probeRTTStart = time.Now()
			cc.priorCwnd = cc.cwnd
			cc.probeRTTDone = false
		}

	case bbrProbeRTT:
		// Reduce cwnd to 4 packets to measure true minRTT
		if !cc.probeRTTDone {
			if cc.bytesInFlight.Load() <= probeRTTCwnd {
				cc.probeRTTDone = true
				cc.probeRTTStart = time.Now()
			}
		}
		// Hold for 200ms then exit
		if cc.probeRTTDone && time.Since(cc.probeRTTStart) > probeRTTDuration {
			cc.minRTTExpiry = time.Now().Add(minRTTWindow)
			cc.state = bbrProbeBW
			cc.cycleIdx = 0
			// Restore cwnd
			cc.cwnd = cc.priorCwnd
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
		// Cycle: 1.25, 0.75, 1.0×6
		gains := []float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}
		gain = gains[cc.cycleIdx%8]
	case bbrProbeRTT:
		// Minimal cwnd during probe
		cc.cwnd = probeRTTCwnd
		cc.pacingRate = int64(float64(cc.maxBW) * 0.5)
		return
	}

	cc.cwnd = int64(float64(bdp) * gain)
	if cc.cwnd < minCwnd {
		cc.cwnd = minCwnd
	}

	cc.pacingRate = int64(float64(cc.maxBW) * gain)

	if cc.maxBandwidth > 0 && cc.pacingRate > cc.maxBandwidth {
		cc.pacingRate = cc.maxBandwidth
	}
}

func (cc *CongestionController) bdp() int64 {
	if cc.maxBW == 0 || cc.minRTT == time.Duration(math.MaxInt64) {
		return initCwnd
	}
	return cc.maxBW * int64(cc.minRTT) / int64(time.Second)
}

func (cc *CongestionController) GetState() string {
	states := []string{"startup", "drain", "probe_bw", "probe_rtt"}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return states[cc.state]
}
