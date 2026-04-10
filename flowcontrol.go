package nrup

import (
	"sync"
	"time"
	"sync/atomic"
)

// FlowControl 流控器
// 发送端不能超过接收端的处理速度
type FlowControl struct {
	mu          sync.Mutex
	recvWindow  int64         // 接收窗口大小
	sendWindow  atomic.Int64  // 当前可发送量
	acked       int64
	maxWindow   int64
}

func NewFlowControl(windowSize int64) *FlowControl {
	if windowSize <= 0 {
		windowSize = 256 * 1024 // 默认256KB窗口
	}
	fc := &FlowControl{
		recvWindow: windowSize,
		maxWindow:  windowSize,
	}
	fc.sendWindow.Store(windowSize)
	return fc
}

// CanSend 检查是否可以发送
func (fc *FlowControl) CanSend(size int64) bool {
	return fc.sendWindow.Load() >= size
}

// OnSend 发送后减少窗口
func (fc *FlowControl) OnSend(size int64) {
	fc.sendWindow.Add(-size)
}

// OnACK 收到ACK后恢复窗口
func (fc *FlowControl) OnACK(size int64) {
	current := fc.sendWindow.Add(size)
	if current > fc.maxWindow {
		fc.sendWindow.Store(fc.maxWindow)
	}
}

// WaitForWindow 等待窗口有空间
func (fc *FlowControl) WaitForWindow(size int64) {
	for fc.sendWindow.Load() < size {
		time.Sleep(100 * time.Microsecond)
	}
	fc.sendWindow.Add(-size)
}
