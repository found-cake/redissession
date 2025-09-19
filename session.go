package session

import (
	"net/http"
	"sync"
	"time"
)

type Session struct {
	mu        sync.RWMutex
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Values    map[string]interface{} `json:"values"`
	IsNew     bool                   `json:"-"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	ExpiresAt time.Time              `json:"expires_at"`
}

func NewSession(id string, maxAge time.Duration) *Session {
	now := time.Now()
	return &Session{
		ID:        id,
		Values:    make(map[string]interface{}),
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(maxAge),
	}
}

func (s *Session) Set(key string, val interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Values[key] = val
	s.UpdatedAt = time.Now()
}

func (s *Session) Get(key string) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Values[key]
}

func (s *Session) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Values, key)
	s.UpdatedAt = time.Now()
}

func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
	store, err := GetStore(r)
	if err != nil {
		return err
	}
	return store.Save(r, w, s)
}
