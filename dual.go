package nrup

import (
	"net"
	"sync/atomic"
	"time"
)

// DualChannel AnyConnect风格双通道
// TCP/TLS = 控制通道 + 备用数据
// UDP/nDTLS = 主数据通道
type DualChannel struct {
	tcp     net.Conn        // 控制通道（TLS）
	udp     *NDTLSConn   // 数据通道（nDTLS）
	
	useUDP  atomic.Bool     // 当前是否用UDP
	mtu     int             // 发现的MTU
	
	// 统计
	udpSent    atomic.Int64
	udpRecv    atomic.Int64
	lastUDPRecv time.Time
	
	closed  atomic.Bool
}

// NewDualChannel 创建双通道
func NewDualChannel(tcp net.Conn, udp *NDTLSConn) *DualChannel {
	dc := &DualChannel{
		tcp: tcp,
		udp: udp,
		mtu: 1400, // 默认MTU
	}
	dc.useUDP.Store(true) // 默认走UDP
	go dc.udpProbe()      // 启动UDP探测
	return dc
}

// Write 发送数据（自动选择通道）
func (dc *DualChannel) Write(p []byte) (int, error) {
	if dc.useUDP.Load() && dc.udp != nil {
		n, err := dc.udp.Write(p)
		if err == nil {
			dc.udpSent.Add(1)
			return n, nil
		}
		// UDP写失败 → 降级TCP
		dc.useUDP.Store(false)
	}
	return dc.tcp.Write(p)
}

// Read 接收数据（从活跃通道读）
func (dc *DualChannel) Read(p []byte) (int, error) {
	if dc.useUDP.Load() && dc.udp != nil {
		// 设短超时，超时则尝试TCP
		dc.udp.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := dc.udp.Read(p)
		if err == nil {
			dc.udpRecv.Add(1)
			dc.lastUDPRecv = time.Now()
			return n, nil
		}
		// UDP读超时 → 降级TCP
		dc.useUDP.Store(false)
	}
	return dc.tcp.Read(p)
}

// udpProbe 持续探测UDP是否可用
func (dc *DualChannel) udpProbe() {
	backoff := 500 * time.Millisecond

	for {
		if dc.closed.Load() {
			return
		}
		if !dc.useUDP.Load() && dc.udp != nil {
			time.Sleep(backoff)
			dc.udp.Write([]byte{0x00}) //nolint:errcheck probe
			time.Sleep(500 * time.Millisecond)
			if time.Since(dc.lastUDPRecv) < 2*time.Second {
				dc.useUDP.Store(true)
				backoff = 500 * time.Millisecond
				notifyState(TransportState{Mode: "nDTLS 1.2", UDPAlive: true})
			} else {
				backoff = backoff * 2
				if backoff > 5*time.Second {
					backoff = 5 * time.Second
				}
			}
		} else {
			time.Sleep(10 * time.Second)
		}
	}
}

// MTU发现（简化版：逐步减小包大小测试）
func (dc *DualChannel) DiscoverMTU() int {
	if dc.udp == nil {
		return 0
	}

	for mtu := 1500; mtu >= 500; mtu -= 100 {
		probe := make([]byte, mtu)
		_, err := dc.udp.Write(probe)
		if err == nil {
			dc.mtu = mtu - dc.udp.Overhead() - 8 // 减去开销
			return dc.mtu
		}
	}
	dc.mtu = 1200 // 安全默认值
	return dc.mtu
}

// GetMTU 获取当前MTU
func (dc *DualChannel) GetMTU() int { return dc.mtu }

// IsUDP 当前是否走UDP
func (dc *DualChannel) IsUDP() bool { return dc.useUDP.Load() }

// Close 关闭
func (dc *DualChannel) Close() error {
	dc.closed.Store(true)
	if dc.udp != nil {
		dc.udp.Close()
	}
	return dc.tcp.Close()
}

// ForceUDP 强制使用UDP
func (dc *DualChannel) ForceUDP() { dc.useUDP.Store(true) }

// ForceTCP 强制使用TCP
func (dc *DualChannel) ForceTCP() { dc.useUDP.Store(false) }

// Stats 统计
func (dc *DualChannel) Stats() DualStats {
	return DualStats{
		UDPActive: dc.useUDP.Load(),
		UDPSent:   dc.udpSent.Load(),
		UDPRecv:   dc.udpRecv.Load(),
		MTU:       dc.mtu,
	}
}

type DualStats struct {
	UDPActive bool
	UDPSent   int64
	UDPRecv   int64
	MTU       int
}

// TransportState 当前传输状态
type TransportState struct {
	Mode     string // "nDTLS 1.2" / "TLS 1.3" / "recovering"
	UDPAlive bool
	RTT      int64  // ms
	Loss     float64
}

// GetState 获取当前传输状态（客户端TUI用）
func (dc *DualChannel) GetState() TransportState {
	state := TransportState{
		UDPAlive: dc.useUDP.Load(),
	}
	if state.UDPAlive {
		state.Mode = "nDTLS 1.2"
	} else {
		state.Mode = "TLS 1.3"
	}
	return state
}

// OnStateChange 状态变化回调
type StateCallback func(TransportState)

var stateCallback StateCallback

// SetStateCallback 设置状态回调（客户端注册）
func SetStateCallback(cb StateCallback) {
	stateCallback = cb
}

// notifyState 通知状态变化
func notifyState(s TransportState) {
	if stateCallback != nil {
		stateCallback(s)
	}
}
