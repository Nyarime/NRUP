package nrup

import (
	"time"
)

// Keepalive 连接保活
type Keepalive struct {
	conn     *Conn
	interval time.Duration
	timeout  time.Duration
	lastRecv time.Time
}

// StartKeepalive 启动保活
func (c *Conn) StartKeepalive(interval, timeout time.Duration) {
	ka := &Keepalive{
		conn:     c,
		interval: interval,
		timeout:  timeout,
		lastRecv: time.Now(),
	}
	go ka.sendLoop()
	go ka.checkLoop()
}

func (ka *Keepalive) sendLoop() {
	ticker := time.NewTicker(ka.interval)
	for range ticker.C {
		if ka.conn.closed.Load() {
			return
		}
		ts := uint64(time.Now().UnixMilli())
		frame := EncodePingFrame(ts)
		if _, err := ka.conn.dtls.Write(frame); err != nil { return }
	}
}

func (ka *Keepalive) checkLoop() {
	ticker := time.NewTicker(ka.timeout)
	for range ticker.C {
		if ka.conn.closed.Load() {
			return
		}
		if time.Since(ka.lastRecv) > ka.timeout {
			ka.conn.Close()
			return
		}
	}
}

// OnRecvPing 收到Ping时更新
func (ka *Keepalive) OnRecvPing() {
	ka.lastRecv = time.Now()
}
