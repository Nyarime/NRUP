package nrup

import (
	"sync"
	"sync/atomic"
)

// FlowControl receiver-side flow control
type FlowControl struct {
	mu        sync.Mutex
	cond      *sync.Cond
	sendWindow atomic.Int64
	maxWindow  int64
}

func NewFlowControl(windowSize int64) *FlowControl {
	if windowSize <= 0 {
		windowSize = 256 * 1024 // 256KB default
	}
	fc := &FlowControl{
		maxWindow: windowSize,
	}
	fc.cond = sync.NewCond(&fc.mu)
	fc.sendWindow.Store(windowSize)
	return fc
}

func (fc *FlowControl) CanSend(size int64) bool {
	return fc.sendWindow.Load() >= size
}

func (fc *FlowControl) OnSend(size int64) {
	fc.sendWindow.Add(-size)
}

func (fc *FlowControl) OnACK(size int64) {
	current := fc.sendWindow.Add(size)
	if current > fc.maxWindow {
		fc.sendWindow.Store(fc.maxWindow)
	}
	// Wake up waiters
	fc.cond.Broadcast()
}

// WaitForWindow blocks until window has space
func (fc *FlowControl) WaitForWindow(size int64) {
	fc.mu.Lock()
	for fc.sendWindow.Load() < size {
		fc.cond.Wait() // efficient wait, no CPU burn
	}
	fc.mu.Unlock()
	fc.sendWindow.Add(-size)
}
