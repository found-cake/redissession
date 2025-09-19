package session

import (
	"context"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store interface {
	Get(r *http.Request, name string) (*Session, error)
	New(r *http.Request, name string) (*Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *Session) error
}

type RedisStore struct {
	client  *redis.Client
	prefix  string
	crypto  *Crypto
	options *CookieOptions
}

func NewRedisStore(client *redis.Client, keyPrefix string, crypto *Crypto, options *CookieOptions) *RedisStore {
	return &RedisStore{
		client:  client,
		prefix:  keyPrefix,
		crypto:  crypto,
		options: options,
	}
}

func (s *RedisStore) Get(r *http.Request, name string) (*Session, error) {
	return s.New(r, name)
}

func (s *RedisStore) New(r *http.Request, name string) (*Session, error) {
	var session *Session
	cookie, err := r.Cookie(name)
	if err == nil {
		loaded, err := s.load(r.Context(), name, cookie.Value)
		if err == nil {
			session = loaded
			session.IsNew = false
		}
	}
	if session == nil {
		id, err := s.crypto.GenerateSessionID()
		if err != nil {
			return nil, err
		}
		session = NewSession(id, time.Duration(s.options.MaxAge)*time.Second)
		session.IsNew = true
	}
	return session, nil
}

func (s *RedisStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	key := s.redisKey(session.Name, session.ID)
	encrypted, err := s.crypto.EncryptAndSign(session)
	if err != nil {
		return err
	}
	ttl := time.Until(session.ExpiresAt)
	if err := s.client.Set(r.Context(), key, encrypted, ttl).Err(); err != nil {
		return err
	}

	http.SetCookie(w, s.options.NewCookie(session.Name, session.ID))
	return nil
}

func (s *RedisStore) load(ctx context.Context, name, sessionID string) (*Session, error) {
	key := s.redisKey(name, sessionID)
	encrypted, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	var session Session
	if err := s.crypto.DecryptAndVerify(encrypted, &session); err != nil {
		return nil, err
	}
	session.Name = name
	return &session, nil
}

func (s *RedisStore) redisKey(name string, sessionID string) string {
	return s.prefix + name + ":" + sessionID
}

type storeContextKey struct{}

func GetStore(r *http.Request) (Store, error) {
	if store, ok := r.Context().Value(storeContextKey{}).(Store); ok {
		return store, nil
	}
	return nil, ErrStoreNotFound
}
