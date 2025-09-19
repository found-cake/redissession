package session

import "net/http"

type CookieOptions struct {
	Path        string
	Domain      string
	MaxAge      int // seconds
	Secure      bool
	HttpOnly    bool
	Partitioned bool
	SameSite    http.SameSite
}

func (options *CookieOptions) NewCookie(name string, value string) *http.Cookie {
	return &http.Cookie{
		Name:        name,
		Value:       value,
		Path:        options.Path,
		Domain:      options.Domain,
		MaxAge:      options.MaxAge,
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
