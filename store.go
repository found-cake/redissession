package redissession

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

var rotateSessionScript = redis.NewScript(`
  redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
  redis.call('DEL', KEYS[1])
  return 1
`)

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
			session.setIsNew(false)
		}
	}
	if session == nil {
		id, err := s.crypto.GenerateSessionID()
		if err != nil {
			return nil, err
		}
		session = NewSession(id, time.Duration(s.options.MaxAge)*time.Second)
		session.setIsNew(true)
	}
	session.setName(name)
	return session, nil
}

func (s *RedisStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	key := s.redisKey(session.Name(), session.ID())
	ttl := time.Until(session.ExpiresAt())

	if ttl <= 0 {
		return ErrSessionExpired
	}
	encrypted, err := s.crypto.EncryptAndSign(session, []byte(session.Name()))
	if err != nil {
		return err
	}
	if err := s.client.Set(r.Context(), key, encrypted, ttl).Err(); err != nil {
		return err
	}

	cookie := s.options.NewCookie(session)
	http.SetCookie(w, cookie)
	return nil
}

func (s *RedisStore) RotateID(r *http.Request, w http.ResponseWriter, session *Session) error {
	ctx := r.Context()

	oldID := session.ID()
	oldKey := s.redisKey(session.Name(), oldID)

	newID, err := s.crypto.GenerateSessionID()
	if err != nil {
		return err
	}
	session.setID(newID)
	newKey := s.redisKey(session.Name(), newID)

	ttl := time.Until(session.ExpiresAt())
	if ttl <= 0 {
		ttl = time.Second
	}

	encrypted, err := s.crypto.EncryptAndSign(session, []byte(session.Name()))
	if err != nil {
		return err
	}

	if err := rotateSessionScript.Run(ctx, s.client, []string{oldKey, newKey}, encrypted, ttl.Milliseconds()).Err(); err != nil {
		return err
	}

	http.SetCookie(w, s.options.NewCookie(session))
	return nil
}

func (s *RedisStore) Destroy(r *http.Request, w http.ResponseWriter, session *Session) error {
	key := s.redisKey(session.Name(), session.ID())
	if err := s.client.Del(r.Context(), key).Err(); err != nil {
		return err
	}
	expiredCookie := s.options.RemoveCookie(session.name)
	http.SetCookie(w, expiredCookie)
	return nil
}

func (s *RedisStore) load(ctx context.Context, name, sessionID string) (*Session, error) {
	key := s.redisKey(name, sessionID)
	encrypted, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	var session Session
	session.setName(name)
	if err := s.crypto.DecryptAndVerify(encrypted, &session, []byte(session.Name())); err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt()) {
		s.client.Del(ctx, key)
		return nil, ErrSessionExpired
	}

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
