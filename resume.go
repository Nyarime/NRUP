package nrup
// TODO: 0-RTT需要UDPConn多路分发支持（当前Listener只能服务单连接）

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// SessionCache 会话缓存（0-RTT快速重连）

type CachedSession struct {
	Key       []byte
	CreatedAt time.Time
	TTL       time.Duration
}




// 0-RTT Resume帧格式:
// [1B type=0x04][32B sessionID][32B HMAC(key, timestamp)]

const frameResume = 0x04

// clientResume 尝试0-RTT恢复
func clientResume(conn *net.UDPConn, serverAddr *net.UDPAddr, sessionID string) ([]byte, bool) {
	key, ok := globalStore.Get(sessionID)
	if !ok {
		return nil, false
	}

	// 构造Resume帧
	frame := make([]byte, 1+32+32)
	frame[0] = frameResume
	copy(frame[1:33], []byte(sessionID)[:32])

	// HMAC(key, timestamp) 防重放
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	mac := hmac.New(sha256.New, key)
	mac.Write(ts)
	copy(frame[33:65], mac.Sum(nil)[:32])

	conn.WriteToUDP(frame, serverAddr)

	// 等确认
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := conn.ReadFromUDP(buf)
	conn.SetReadDeadline(time.Time{})

	if err != nil || n < 1 || buf[0] != frameResume {
		return nil, false // 恢复失败，走完整握手
	}

	return key, true
}

// serverResume 处理0-RTT恢复请求
func serverResume(conn net.PacketConn, clientAddr net.Addr, frame []byte) ([]byte, string, bool) {
	if len(frame) < 65 || frame[0] != frameResume {
		return nil, "", false
	}

	sessionID := string(frame[1:33])
	key, ok := globalStore.Get(sessionID)
	if !ok {
		return nil, "", false
	}

	// 验证HMAC（5分钟窗口）
	clientMAC := frame[33:65]
	now := time.Now().Unix()
	for offset := int64(-300); offset <= 0; offset++ {
		ts := make([]byte, 8)
		binary.BigEndian.PutUint64(ts, uint64(now+offset))
		mac := hmac.New(sha256.New, key)
		mac.Write(ts)
		if hmac.Equal(clientMAC, mac.Sum(nil)[:32]) {
			// 发确认
			ack := []byte{frameResume}
			conn.WriteTo(ack, clientAddr)
			return key, sessionID, true
		}
	}

	return nil, "", false
}

// 清理过期缓存
// SessionStore 会话持久化接口
// 默认用内存。可实现Redis/文件版本用于跨重启恢复。
type SessionStore interface {
	Save(sessionID string, key []byte, ttl time.Duration) error
	Get(sessionID string) ([]byte, bool)
	Delete(sessionID string)
}

// SetSessionStore 替换全局会话存储（启动时调用）
func SetSessionStore(store SessionStore) {
	globalStore = store
}

var globalStore SessionStore = &memoryStore{sessions: make(map[string]*CachedSession)}

// memoryStore 内存存储（默认）
type memoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*CachedSession
}

func (m *memoryStore) Save(sessionID string, key []byte, ttl time.Duration) error {
	m.mu.Lock()
	m.sessions[sessionID] = &CachedSession{Key: key, CreatedAt: time.Now(), TTL: ttl}
	m.mu.Unlock()
	return nil
}

func (m *memoryStore) Get(sessionID string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	if !ok || time.Since(s.CreatedAt) > s.TTL {
		return nil, false
	}
	return s.Key, true
}

func (m *memoryStore) Delete(sessionID string) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			if ms, ok := globalStore.(*memoryStore); ok {
				ms.mu.Lock()
				now := time.Now()
				for id, s := range ms.sessions {
					if now.Sub(s.CreatedAt) > s.TTL {
						delete(ms.sessions, id)
					}
				}
				ms.mu.Unlock()
			}
		}
	}()
}
