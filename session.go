package nrup

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// SessionManager 会话管理（快速重连）
// 记住之前的密钥，断线后不用重新握手
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

type Session struct {
	ID        string
	Key       []byte    // 会话密钥
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
	}
	go sm.cleanup()
	return sm
}

// Create 创建新会话
func (sm *SessionManager) Create(key []byte, ttl time.Duration) string {
	id := generateSessionID()
	sm.mu.Lock()
	sm.sessions[id] = &Session{
		ID:        id,
		Key:       key,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}
	sm.mu.Unlock()
	return id
}

// Resume 恢复会话（快速重连）
func (sm *SessionManager) Resume(id string) ([]byte, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	sess, ok := sm.sessions[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, false
	}
	return sess.Key, true
}

// Remove 删除会话
func (sm *SessionManager) Remove(id string) {
	sm.mu.Lock()
	delete(sm.sessions, id)
	sm.mu.Unlock()
}

func (sm *SessionManager) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, sess := range sm.sessions {
			if now.After(sess.ExpiresAt) {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
