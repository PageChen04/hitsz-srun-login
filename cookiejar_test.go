package main

import (
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
)

func TestPersistentCookieJarCanSkipLoadingAndStillSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	endpoint, err := url.Parse("https://ids.hit.edu.cn/")
	if err != nil {
		t.Fatal(err)
	}

	oldJar, err := newPersistentCookieJar(path, false)
	if err != nil {
		t.Fatal(err)
	}
	oldJar.SetCookies(endpoint, []*http.Cookie{{Name: "session", Value: "old"}})
	if err := oldJar.Save(); err != nil {
		t.Fatal(err)
	}

	freshJar, err := newPersistentCookieJar(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := freshJar.Cookies(endpoint); len(got) != 0 {
		t.Fatalf("cookies loaded despite load=false: %v", got)
	}
	freshJar.SetCookies(endpoint, []*http.Cookie{{Name: "session", Value: "new"}})
	if err := freshJar.Save(); err != nil {
		t.Fatal(err)
	}

	loadedJar, err := newPersistentCookieJar(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cookies := loadedJar.Cookies(endpoint)
	if len(cookies) != 1 || cookies[0].Value != "new" {
		t.Fatalf("saved cookies = %v, want new session", cookies)
	}
}
