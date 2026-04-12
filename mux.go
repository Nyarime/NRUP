package nrup

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

// Mux 多路复用器——一个NRUP连接承载多个Stream
type Mux struct {
	conn    *Conn
	streams sync.Map    // streamID → *Stream
	nextID  atomic.Uint32
	accepts chan *Stream // Accept()返回的新stream
	closed  atomic.Bool
}

// Stream 多路复用中的单个流
type Stream struct {
	id     uint32
	mux    *Mux
	readCh chan []byte // 接收队列
	closed atomic.Bool
}

// NewMux 在NRUP连接上创建多路复用器
func NewMux(conn *Conn) *Mux {
	m := &Mux{
		conn:    conn,
		accepts: make(chan *Stream, 32),
	}
	go m.readLoop()
	return m
}

// Open 打开新Stream
func (m *Mux) Open() (*Stream, error) {
	if m.closed.Load() {
		return nil, errors.New("mux closed")
	}
	id := m.nextID.Add(1)
	s := &Stream{
		id:     id,
		mux:    m,
		readCh: make(chan []byte, 64),
	}
	m.streams.Store(id, s)
	return s, nil
}

// Accept 接受对方打开的Stream
func (m *Mux) Accept() (*Stream, error) {
	s, ok := <-m.accepts
	if !ok {
		return nil, errors.New("mux closed")
	}
	return s, nil
}

// Close 关闭多路复用器
func (m *Mux) Close() error {
	m.closed.Store(true)
	close(m.accepts)
	return m.conn.Close()
}

// readLoop 读取底层连接，分发到各Stream
func (m *Mux) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := m.conn.Read(buf)
		if err != nil || n < 4 {
			return
		}

		// 帧格式: [4B streamID][payload]
		streamID := binary.BigEndian.Uint32(buf[:4])
		payload := make([]byte, n-4)
		copy(payload, buf[4:n])

		// 查找或创建Stream
		v, loaded := m.streams.LoadOrStore(streamID, &Stream{
			id:     streamID,
			mux:    m,
			readCh: make(chan []byte, 64),
		})
		s := v.(*Stream)

		if !loaded {
			// 新Stream，通知Accept
			select {
			case m.accepts <- s:
			default:
			}
		}

		// 分发数据
		select {
		case s.readCh <- payload:
		default:
			// 队列满，丢弃（流控由上层处理）
		}
	}
}

// === Stream方法 ===

func (s *Stream) Read(p []byte) (int, error) {
	data, ok := <-s.readCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, data)
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, errors.New("stream closed")
	}
	// 帧格式: [4B streamID][payload]
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(frame[:4], s.id)
	copy(frame[4:], p)
	return s.mux.conn.Write(frame)
}

func (s *Stream) Close() error {
	s.closed.Store(true)
	close(s.readCh)
	s.mux.streams.Delete(s.id)
	return nil
}

// ID 返回Stream ID
func (s *Stream) ID() uint32 {
	return s.id
}
