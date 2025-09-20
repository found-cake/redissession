# RedisSession

A Redis-backed, encrypted, thread-safe HTTP session store for Go.

- Focuses on correctness, simplicity, and practical defaults
- Uses go-redis v9 and modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305)
- Thread-safe session container to prevent concurrent access issues
- Minimal external dependencies

---

## Install

```bash
go get github.com/found-cake/redissession
```

Go version: see [go.mod](./go.mod) (currently Go 1.24).

---

## Quick start

```go
package main

import (
	"net/http"
	"time"

	"github.com/found-cake/redissession"
	"github.com/redis/go-redis/v9"
)

func main() {
	// 1) Create an AEAD cipher
	encKey, _ := redissession.GenerateKey(32) // 32 bytes for AES-256-GCM or (X)ChaCha20-Poly1305
	aead, _ := redissession.NewAESGCM(encKey)

	// 2) Build Crypto (no extra signing key needed; AEAD is authenticated)
	crypto := redissession.NewCrypto(aead, nil)

	// 3) Redis client (go-redis v9)
	client := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
		DB:   0,
	})

	// 4) Cookie options
	opts := redissession.DefaultCookieOptions()
	opts.Secure = true          // set false only for local HTTP
	opts.SameSite = http.SameSiteLaxMode
	opts.MaxAge = 3600          // 1 hour in seconds

	// 5) Create the store
	store := redissession.NewRedisStore(client, "app:", crypto, opts)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Load or create a session named "app_session"
		sess, err := store.New(r, "app_session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Use the session
		if sess.IsNew() {
			sess.Set("visits", 1)
		} else {
			if v, ok := sess.Get("visits").(int); ok {
				sess.Set("visits", v+1)
			}
		}

		// Optional: sliding expiration
		sess.Refresh(time.Duration(opts.MaxAge) * time.Second)

		// Save to Redis and set cookie
		if err := store.Save(r, w, sess); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.ListenAndServe(":8080", nil)
}
```
