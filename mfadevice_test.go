package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type mfaDeviceRoundTripFunc func(*http.Request) (*http.Response, error)

func (f mfaDeviceRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestLoadOrCreateMFABrowserFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "device.json")

	first, created, err := loadOrCreateMFABrowserFingerprint(path)
	if err != nil {
		t.Fatalf("first loadOrCreateMFABrowserFingerprint() error = %v", err)
	}
	if !created {
		t.Fatal("first loadOrCreateMFABrowserFingerprint() did not create a device")
	}
	if _, err := normalizeMFABrowserFingerprint(first); err != nil {
		t.Fatalf("generated fingerprint is invalid: %v", err)
	}

	second, created, err := loadOrCreateMFABrowserFingerprint(path)
	if err != nil {
		t.Fatalf("second loadOrCreateMFABrowserFingerprint() error = %v", err)
	}
	if created {
		t.Fatal("second loadOrCreateMFABrowserFingerprint() unexpectedly created a device")
	}
	if second != first {
		t.Fatalf("fingerprint changed: first=%q second=%q", first, second)
	}
}

func TestLoadMFABrowserFingerprintRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"browser_fingerprint":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMFABrowserFingerprint(path); err == nil {
		t.Fatal("loadMFABrowserFingerprint() unexpectedly accepted invalid data")
	}
}

func TestLoadMFABrowserFingerprintRejectsOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "device.json")
	data := []byte(`{"version":1,"browser_fingerprint":"A84D9F0C19B14629A77B396DFC719E52"}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMFABrowserFingerprint(path); err == nil {
		t.Fatal("loadMFABrowserFingerprint() unexpectedly accepted permissions 0644")
	}
}

func TestSaveMFADeviceDoesNotOverwriteExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.json")
	original := persistedMFADevice{
		Version:            mfaDeviceFileVersion,
		BrowserFingerprint: "A84D9F0C19B14629A77B396DFC719E52",
	}
	if err := saveMFADevice(path, original); err != nil {
		t.Fatal(err)
	}
	replacement := persistedMFADevice{
		Version:            mfaDeviceFileVersion,
		BrowserFingerprint: "B84D9F0C19B14629A77B396DFC719E52",
	}
	if err := saveMFADevice(path, replacement); !errors.Is(err, os.ErrExist) {
		t.Fatalf("saveMFADevice() error = %v, want os.ErrExist", err)
	}
	got, err := loadMFABrowserFingerprint(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != original.BrowserFingerprint {
		t.Fatalf("stored fingerprint = %q, want %q", got, original.BrowserFingerprint)
	}
}

func TestLoadOrCreateMFABrowserFingerprintConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.json")
	const workers = 16
	results := make(chan string, workers)
	errors := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fingerprint, _, err := loadOrCreateMFABrowserFingerprint(path)
			if err != nil {
				errors <- err
				return
			}
			results <- fingerprint
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatalf("loadOrCreateMFABrowserFingerprint() error = %v", err)
	}

	var want string
	for fingerprint := range results {
		if want == "" {
			want = fingerprint
		}
		if fingerprint != want {
			t.Fatalf("concurrent fingerprints differ: got %q, want %q", fingerprint, want)
		}
	}
}

func TestLoadOrCreateMFABrowserFingerprintRecoversStaleLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.json")
	lockPath := path + ".lock"
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-mfaDeviceStaleLockAge - time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	if _, created, err := loadOrCreateMFABrowserFingerprint(path); err != nil {
		t.Fatalf("loadOrCreateMFABrowserFingerprint() error = %v", err)
	} else if !created {
		t.Fatal("loadOrCreateMFABrowserFingerprint() did not create a device")
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale lock still exists: %v", err)
	}
}

func TestLoadOrCreateMFABrowserFingerprintIgnoresCrashTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.json")
	if err := os.WriteFile(filepath.Join(dir, ".device.json.tmp-crash"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	fingerprint, created, err := loadOrCreateMFABrowserFingerprint(path)
	if err != nil {
		t.Fatalf("loadOrCreateMFABrowserFingerprint() error = %v", err)
	}
	if !created {
		t.Fatal("loadOrCreateMFABrowserFingerprint() did not create a device")
	}
	loaded, err := loadMFABrowserFingerprint(path)
	if err != nil {
		t.Fatalf("loadMFABrowserFingerprint() error = %v", err)
	}
	if loaded != fingerprint {
		t.Fatalf("stored fingerprint = %q, want %q", loaded, fingerprint)
	}
}

func TestRegisterMFABrowserFingerprint(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var request *http.Request
	client := &http.Client{
		Jar: jar,
		Transport: mfaDeviceRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			request = req
			header := make(http.Header)
			header.Add("Set-Cookie", mfaBrowserFingerprintCookie+"=A84D9F0C19B14629A77B396DFC719E52; Path=/authserver")
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(`{"success":true}`)),
				Request:    req,
			}, nil
		}),
	}

	fingerprint := "A84D9F0C19B14629A77B396DFC719E52"
	if err := registerMFABrowserFingerprint(client, srunServiceURL, fingerprint); err != nil {
		t.Fatalf("registerMFABrowserFingerprint() error = %v", err)
	}
	if request == nil {
		t.Fatal("registerMFABrowserFingerprint() did not send a request")
	}
	if got := request.URL.Query().Get("bfp"); got != fingerprint {
		t.Fatalf("bfp = %q, want %q", got, fingerprint)
	}
	if got := request.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
		t.Fatalf("X-Requested-With = %q, want XMLHttpRequest", got)
	}
	if got := request.Header.Get("Referer"); !strings.Contains(got, "/authserver/login?service=") {
		t.Fatalf("Referer = %q, want login service URL", got)
	}
}

func TestRegisterMFABrowserFingerprintRejectsMissingCookie(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		Transport: mfaDeviceRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"success":true}`)),
				Request:    req,
			}, nil
		}),
	}

	err = registerMFABrowserFingerprint(client, srunServiceURL, "A84D9F0C19B14629A77B396DFC719E52")
	if err == nil {
		t.Fatal("registerMFABrowserFingerprint() unexpectedly accepted a missing cookie")
	}
}
