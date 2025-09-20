package redissession

import (
	"net/http"
	"time"
)

type CookieOptions struct {
	Path        string
	Domain      string
	MaxAge      int // seconds
	Secure      bool
	HttpOnly    bool
	Partitioned bool
	SameSite    http.SameSite
}

func (options *CookieOptions) NewCookie(session *Session) *http.Cookie {
	return &http.Cookie{
		Name:        session.Name(),
		Value:       session.ID(),
		Path:        options.Path,
		Domain:      options.Domain,
		MaxAge:      int(time.Until(session.ExpiresAt()).Seconds()),
		Expires:     session.ExpiresAt(),
		Secure:      options.Secure,
		HttpOnly:    options.HttpOnly,
		Partitioned: options.Partitioned,
		SameSite:    options.SameSite,
	}
}

func (options *CookieOptions) RemoveCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:        name,
		Value:       "",
		Path:        options.Path,
		Domain:      options.Domain,
		MaxAge:      -1,
		Expires:     time.Unix(0, 0),
		Secure:      options.Secure,
		HttpOnly:    options.HttpOnly,
		Partitioned: options.Partitioned,
		SameSite:    options.SameSite,
	}
}

func DefaultCookieOptions() *CookieOptions {
	return &CookieOptions{
		Path:     "/",
		MaxAge:   86400 * 30, // 30 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}
