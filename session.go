package session

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type Session struct {
	mu        sync.RWMutex
	id        string
	name      string
	values    map[string]interface{}
	isNew     bool
	createdAt time.Time
	updatedAt time.Time
	expiresAt time.Time
}

func NewSession(id string, maxAge time.Duration) *Session {
	now := time.Now()
	return &Session{
		id:        id,
		values:    make(map[string]interface{}),
		isNew:     true,
		createdAt: now,
		updatedAt: now,
		expiresAt: now.Add(maxAge),
	}
}

func (s *Session) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id
}

func (s *Session) Name() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.name
}

func (s *Session) IsNew() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isNew
}

func (s *Session) CreatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.createdAt
}

func (s *Session) UpdatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.updatedAt
}

func (s *Session) ExpiresAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.expiresAt
}

func (s *Session) Set(key string, val interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = make(map[string]interface{})
	}
	s.values[key] = val
	s.updatedAt = time.Now()
}

func (s *Session) Get(key string) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.values[key]
}

func (s *Session) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	s.updatedAt = time.Now()
}

func (s *Session) Refresh(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.expiresAt = now.Add(maxAge)
	s.updatedAt = now
}

func (s *Session) Extend(delta time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expiresAt = s.expiresAt.Add(delta)
	s.updatedAt = time.Now()
}

func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
	store, err := GetStore(r)
	if err != nil {
		return err
	}
	return store.Save(r, w, s)
}

func (s *Session) setName(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.name = name
}

func (s *Session) setIsNew(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isNew = v
}

func (s *Session) setID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = id
}

type sessionDTO struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Values    map[string]interface{} `json:"values"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	ExpiresAt time.Time              `json:"expires_at"`
}

var (
	_ json.Marshaler   = (*Session)(nil)
	_ json.Unmarshaler = (*Session)(nil)
)

func (s *Session) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dto := sessionDTO{
		ID:        s.id,
		Name:      s.name,
		Values:    s.values,
		CreatedAt: s.createdAt,
		UpdatedAt: s.updatedAt,
		ExpiresAt: s.expiresAt,
	}
	return json.Marshal(&dto)
}

func (s *Session) UnmarshalJSON(b []byte) error {
	var dto sessionDTO
	if err := json.Unmarshal(b, &dto); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.id = dto.ID
	s.name = dto.Name

	if dto.Values == nil {
		s.values = make(map[string]interface{})
	} else {
		s.values = dto.Values
	}
	s.createdAt = dto.CreatedAt
	s.updatedAt = dto.UpdatedAt
	s.expiresAt = dto.ExpiresAt

	s.isNew = false
	return nil
}
