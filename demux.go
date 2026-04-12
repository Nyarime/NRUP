package nrup

import (
	"net"
	"time"
	"sync"
)

// udpDemux UDP包分发器——按源地址路由到不同连接
type udpDemux struct {
	conn     *net.UDPConn
	routes   sync.Map          // clientAddr string → chan []byte
	newConns chan *demuxedConn  // 新连接通知
	closed   chan struct{}
}

// demuxedConn 被分发后的虚拟连接（每个客户端一个）
type demuxedConn struct {
	udpConn    *net.UDPConn
	remoteAddr *net.UDPAddr
	recvCh     chan []byte
	demux      *udpDemux
	closeOnce  sync.Once
	closed     chan struct{}
}

func newUDPDemux(conn *net.UDPConn) *udpDemux {
	d := &udpDemux{
		conn:     conn,
		newConns: make(chan *demuxedConn, 32),
		closed:   make(chan struct{}),
	}
	go d.readLoop()
	return d
}

func (d *udpDemux) readLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-d.closed:
			return
		default:
		}

		n, addr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		key := addr.String()
		data := make([]byte, n)
		copy(data, buf[:n])

		// 查找已有连接
		if v, ok := d.routes.Load(key); ok {
			dc := v.(*demuxedConn)
			select {
			case dc.recvCh <- data:
			case <-dc.closed:
			default:
			}
			continue
		}

		// 新连接
		dc := &demuxedConn{
			udpConn:    d.conn,
			remoteAddr: addr,
			recvCh:     make(chan []byte, 256),
			demux:      d,
			closed:     make(chan struct{}),
		}
		dc.recvCh <- data // 第一个包
		d.routes.Store(key, dc)

		select {
		case d.newConns <- dc:
		default:
		}
	}
}

func (d *udpDemux) close() {
	close(d.closed)
}

// net.PacketConn接口实现——让nDTLS以为自己有独立连接
func (dc *demuxedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case data, ok := <-dc.recvCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n = copy(p, data)
		return n, dc.remoteAddr, nil
	case <-dc.closed:
		return 0, nil, net.ErrClosed
	}
}

func (dc *demuxedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return dc.udpConn.WriteTo(p, addr)
}

func (dc *demuxedConn) Close() error {
	dc.closeOnce.Do(func() {
		dc.demux.routes.Delete(dc.remoteAddr.String())
		close(dc.closed)
	})
	return nil
}

func (dc *demuxedConn) LocalAddr() net.Addr {
	return dc.udpConn.LocalAddr()
}

func (dc *demuxedConn) SetDeadline(t time.Time) error { return nil }
func (dc *demuxedConn) SetReadDeadline(t time.Time) error { return nil }
func (dc *demuxedConn) SetWriteDeadline(t time.Time) error { return nil }
