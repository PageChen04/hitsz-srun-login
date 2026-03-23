package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type persistentCookieJar struct {
	inner *cookiejar.Jar
	path  string
}

type persistedCookie struct {
	URL        string    `json:"url"`
	Name       string    `json:"name"`
	Value      string    `json:"value"`
	Path       string    `json:"path,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	Expires    time.Time `json:"expires,omitempty"`
	RawExpires string    `json:"raw_expires,omitempty"`
	MaxAge     int       `json:"max_age,omitempty"`
	Secure     bool      `json:"secure,omitempty"`
	HttpOnly   bool      `json:"http_only,omitempty"`
	SameSite   int       `json:"same_site,omitempty"`
}

func newPersistentCookieJar(path string) (*persistentCookieJar, error) {
	inner, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	jar := &persistentCookieJar{
		inner: inner,
		path:  path,
	}
	if err := jar.Load(); err != nil {
		return nil, err
	}
	return jar, nil
}

func (j *persistentCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.inner.SetCookies(u, cookies)
}

func (j *persistentCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.inner.Cookies(u)
}

func (j *persistentCookieJar) Load() error {
	if j.path == "" {
		return nil
	}

	data, err := os.ReadFile(j.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var stored []persistedCookie
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("decode session file: %w", err)
	}

	now := time.Now()
	for _, item := range stored {
		if !item.Expires.IsZero() && !item.Expires.After(now) {
			continue
		}
		u, err := url.Parse(item.URL)
		if err != nil {
			continue
		}
		j.inner.SetCookies(u, []*http.Cookie{{
			Name:       item.Name,
			Value:      item.Value,
			Path:       item.Path,
			Domain:     item.Domain,
			Expires:    item.Expires,
			RawExpires: item.RawExpires,
			MaxAge:     item.MaxAge,
			Secure:     item.Secure,
			HttpOnly:   item.HttpOnly,
			SameSite:   http.SameSite(item.SameSite),
		}})
	}
	return nil
}

func (j *persistentCookieJar) Save() error {
	if j.path == "" {
		return nil
	}

	var stored []persistedCookie
	for _, rawURL := range sessionCookieURLs() {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		for _, cookie := range j.inner.Cookies(u) {
			stored = append(stored, persistedCookie{
				URL:        rawURL,
				Name:       cookie.Name,
				Value:      cookie.Value,
				Path:       cookie.Path,
				Domain:     cookie.Domain,
				Expires:    cookie.Expires,
				RawExpires: cookie.RawExpires,
				MaxAge:     cookie.MaxAge,
				Secure:     cookie.Secure,
				HttpOnly:   cookie.HttpOnly,
				SameSite:   int(cookie.SameSite),
			})
		}
	}

	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(j.path, data, 0o600)
}

func defaultSessionFile() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil || cacheDir == "" {
		return ".hitsz-srun-login-session.json"
	}
	return filepath.Join(cacheDir, "hitsz-srun-login", "session.json")
}

func sessionCookieURLs() []string {
	return []string{
		"https://ids.hit.edu.cn/",
		"https://net.hitsz.edu.cn/",
	}
}
