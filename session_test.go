package redissession

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func setupTestRedis(t *testing.T) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Redis connection failed: %v", err)
	}
	client.FlushDB(ctx)
	t.Cleanup(func() {
		client.FlushDB(ctx)
		client.Close()
	})
	return client
}

func setupTestCrypto(t *testing.T) *Crypto {
	encKey := make([]byte, 32)
	signKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("rand.Read encKey: %v", err)
	}
	if _, err := rand.Read(signKey); err != nil {
		t.Fatalf("rand.Read signKey: %v", err)
	}
	aead, err := NewAESGCM(encKey)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	return NewCrypto(aead, signKey)
}

func TestSession_ConcurrentAccess(t *testing.T) {
	session := NewSession("test-id", time.Hour)
	done := make(chan bool, 20)
	for i := 0; i < 10; i++ {
		go func(i int) {
			session.Set("user", i)
			got := session.Get("user")
			if got != i {
				t.Errorf("Set/Get mismatch: want %v, got %v", i, got)
			}
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		go func() {
			_ = session.ID()
			done <- true
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestCrypto_EncryptDecrypt(t *testing.T) {
	crypto := setupTestCrypto(t)
	data := map[string]interface{}{"user": "alice", "id": 1}
	enc, err := crypto.EncryptAndSign(data)
	if err != nil {
		t.Fatalf("EncryptAndSign error: %v", err)
	}
	var out map[string]interface{}
	if err := crypto.DecryptAndVerify(enc, &out); err != nil {
		t.Fatalf("DecryptAndVerify error: %v", err)
	}
	if out["user"] != "alice" {
		t.Errorf("Decrypted user mismatch: want alice, got %v", out["user"])
	}
}

func TestCrypto_SignatureTamper(t *testing.T) {
	crypto := setupTestCrypto(t)
	data := map[string]string{"msg": "hello"}
	enc, err := crypto.EncryptAndSign(data)
	if err != nil {
		t.Fatalf("EncryptAndSign error: %v", err)
	}
	// 변조
	if len(enc) < 10 {
		t.Skip("encrypted data too short")
	}
	tampered := enc[:len(enc)-5] + "abcde"
	var out map[string]string
	err = crypto.DecryptAndVerify(tampered, &out)
	if err == nil {
		t.Errorf("expected signature error, got nil")
	}
}

func TestRedisStore_SessionLifecycle(t *testing.T) {
	client := setupTestRedis(t)
	crypto := setupTestCrypto(t)
	options := DefaultCookieOptions()
	options.MaxAge = 10
	options.Secure = false      // 테스트 환경!
	options.Partitioned = false // 기본값
	options.SameSite = http.SameSiteDefaultMode
	store := NewRedisStore(client, "test:", crypto, options)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	session, err := store.New(req, "session-name")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if !session.IsNew() {
		t.Errorf("session should be new")
	}
	session.Set("user", "alice")
	if err := store.Save(req, w, session); err != nil {
		t.Fatalf("Save error: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session-name" {
		t.Errorf("cookie not set properly %d", len(cookies))
	}
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(cookies[0])
	session2, err := store.New(req2, "session-name")
	if err != nil {
		t.Fatalf("restore error: %v", err)
	}
	if session2.Get("user") != "alice" {
		t.Errorf("restored session data mismatch")
	}
}

func TestRedisStore_Expiry(t *testing.T) {
	client := setupTestRedis(t)
	crypto := setupTestCrypto(t)
	options := DefaultCookieOptions()
	options.MaxAge = 1 // 1초
	store := NewRedisStore(client, "test:", crypto, options)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	session, err := store.New(req, "session-name")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	session.Set("foo", "bar")
	if err := store.Save(req, w, session); err != nil {
		t.Fatalf("Save error: %v", err)
	}
	time.Sleep(2 * time.Second)
	cookies := w.Result().Cookies()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(cookies[0])
	session2, err := store.New(req2, "session-name")
	if err != nil {
		t.Fatalf("restore error: %v", err)
	}
	if session2.Get("foo") != nil {
		t.Errorf("expired session should not have old data")
	}
	if !session2.IsNew() {
		t.Errorf("expired session should be new")
	}
}
