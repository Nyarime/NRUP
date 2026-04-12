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
type SessionCache struct {
	mu       sync.RWMutex
	sessions map[string]*CachedSession
}

type CachedSession struct {
	Key       []byte
	CreatedAt time.Time
	TTL       time.Duration
}

var globalCache = &SessionCache{
	sessions: make(map[string]*CachedSession),
}

// Save 缓存会话密钥
func (sc *SessionCache) Save(sessionID string, key []byte, ttl time.Duration) {
	sc.mu.Lock()
	sc.sessions[sessionID] = &CachedSession{
		Key:       key,
		CreatedAt: time.Now(),
		TTL:       ttl,
	}
	sc.mu.Unlock()
}

// Get 获取缓存的密钥
func (sc *SessionCache) Get(sessionID string) ([]byte, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	s, ok := sc.sessions[sessionID]
	if !ok || time.Since(s.CreatedAt) > s.TTL {
		return nil, false
	}
	return s.Key, true
}

// 0-RTT Resume帧格式:
// [1B type=0x04][32B sessionID][32B HMAC(key, timestamp)]

const frameResume = 0x04

// clientResume 尝试0-RTT恢复
func clientResume(conn *net.UDPConn, serverAddr *net.UDPAddr, sessionID string) ([]byte, bool) {
	key, ok := globalCache.Get(sessionID)
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
func serverResume(conn *net.UDPConn, clientAddr *net.UDPAddr, frame []byte) ([]byte, string, bool) {
	if len(frame) < 65 || frame[0] != frameResume {
		return nil, "", false
	}

	sessionID := string(frame[1:33])
	key, ok := globalCache.Get(sessionID)
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
			conn.WriteToUDP(ack, clientAddr)
			return key, sessionID, true
		}
	}

	return nil, "", false
}

// 清理过期缓存
func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			globalCache.mu.Lock()
			now := time.Now()
			for id, s := range globalCache.sessions {
				if now.Sub(s.CreatedAt) > s.TTL {
					delete(globalCache.sessions, id)
				}
			}
			globalCache.mu.Unlock()
		}
	}()
}
