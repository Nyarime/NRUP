package nrup

import (
	"time"
)

// Keepalive 心跳保活（自适应间隔）
type Keepalive struct {
	conn     *Conn
	interval time.Duration
	timeout  time.Duration
	lastRecv time.Time
	minRTT   time.Duration
}

func NewKeepalive(conn *Conn, interval, timeout time.Duration) *Keepalive {
	ka := &Keepalive{
		conn:     conn,
		interval: interval,
		timeout:  timeout,
		lastRecv: time.Now(),
		minRTT:   100 * time.Millisecond,
	}
	go ka.sendLoop()
	go ka.checkLoop()
	return ka
}

func (ka *Keepalive) sendLoop() {
	for {
		// 自适应间隔：RTT低时间隔长，RTT高时间隔短
		interval := ka.interval
		if ka.minRTT < 50*time.Millisecond {
			interval = ka.interval * 2 // 低延迟网络，减少心跳
		} else if ka.minRTT > 200*time.Millisecond {
			interval = ka.interval / 2 // 高延迟网络，增加心跳
		}

		time.Sleep(interval)
		if ka.conn.closed.Load() { return }

		ts := uint64(time.Now().UnixMilli())
		frame := EncodePingFrame(ts)
		if _, err := ka.conn.dtls.Write(frame); err != nil { return }
	}
}

func (ka *Keepalive) checkLoop() {
	ticker := time.NewTicker(ka.timeout)
	for range ticker.C {
		if ka.conn.closed.Load() { return }
		if time.Since(ka.lastRecv) > ka.timeout {
			ka.conn.Close()
			return
		}
	}
}

func (ka *Keepalive) OnRecvPing() {
	ka.lastRecv = time.Now()
}

// UpdateRTT 更新RTT供自适应间隔使用
func (ka *Keepalive) UpdateRTT(rtt time.Duration) {
	if rtt > 0 && rtt < ka.minRTT {
		ka.minRTT = rtt
	}
}
