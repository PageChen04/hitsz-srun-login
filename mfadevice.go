package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	mfaBrowserFingerprintCookie = "MULTIFACTOR_BROWSER_FINGERPRINT"
	mfaDeviceFileVersion        = 1
	mfaDeviceLockWait           = 2 * time.Second
	mfaDeviceStaleLockAge       = 30 * time.Second
)

type persistedMFADevice struct {
	Version            int       `json:"version"`
	BrowserFingerprint string    `json:"browser_fingerprint"`
	CreatedAt          time.Time `json:"created_at"`
}

func defaultMFADeviceFile() string {
	var configDir string
	var err error
	if runtime.GOOS == "windows" {
		// UserCacheDir maps to LocalAppData on Windows, so the credential does
		// not roam to another machine with the user's roaming profile.
		configDir, err = os.UserCacheDir()
	} else {
		configDir, err = os.UserConfigDir()
	}
	if err != nil || configDir == "" {
		return ".hitsz-srun-login-mfa-device.json"
	}
	return filepath.Join(configDir, "hitsz-srun-login", "mfa-device.json")
}

func loadOrCreateMFABrowserFingerprint(path string) (fingerprint string, created bool, err error) {
	if strings.TrimSpace(path) == "" {
		return "", false, errors.New("MFA device file path is empty")
	}

	fingerprint, err = loadMFABrowserFingerprint(path)
	if err == nil {
		return fingerprint, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}

	fingerprint, err = generateMFABrowserFingerprint()
	if err != nil {
		return "", false, err
	}
	device := persistedMFADevice{
		Version:            mfaDeviceFileVersion,
		BrowserFingerprint: fingerprint,
		CreatedAt:          time.Now().UTC(),
	}
	if err := saveMFADevice(path, device); err != nil {
		if errors.Is(err, os.ErrExist) {
			fingerprint, loadErr := loadMFABrowserFingerprint(path)
			if loadErr != nil {
				return "", false, fmt.Errorf("load concurrently created MFA device file: %w", loadErr)
			}
			return fingerprint, false, nil
		}
		return "", false, err
	}
	return fingerprint, true, nil
}

func loadMFABrowserFingerprint(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("MFA device file permissions %04o are too open; use 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var device persistedMFADevice
	if err := json.Unmarshal(data, &device); err != nil {
		return "", fmt.Errorf("decode MFA device file: %w", err)
	}
	if device.Version != mfaDeviceFileVersion {
		return "", fmt.Errorf("unsupported MFA device file version %d", device.Version)
	}
	fingerprint, err := normalizeMFABrowserFingerprint(device.BrowserFingerprint)
	if err != nil {
		return "", fmt.Errorf("invalid MFA device file: %w", err)
	}
	return fingerprint, nil
}

func saveMFADevice(path string, device persistedMFADevice) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create MFA device directory: %w", err)
	}

	lockPath := path + ".lock"
	if err := acquireMFADeviceLock(lockPath); err != nil {
		return err
	}
	defer os.Remove(lockPath)

	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("create MFA device file: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check MFA device file: %w", err)
	}

	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary MFA device file: %w", err)
	}
	tempPath := file.Name()
	defer func() {
		file.Close()
		os.Remove(tempPath)
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("set MFA device file permissions: %w", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(device); err != nil {
		return fmt.Errorf("encode MFA device file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync MFA device file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close MFA device file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("install MFA device file: %w", err)
	}
	return nil
}

func acquireMFADeviceLock(lockPath string) error {
	deadline := time.Now().Add(mfaDeviceLockWait)
	for {
		err := os.Mkdir(lockPath, 0o700)
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create MFA device lock: %w", err)
		}

		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > mfaDeviceStaleLockAge {
			if removeErr := os.Remove(lockPath); removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
				continue
			}
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for MFA device file lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func warnIfMFADeviceFileMayBeShared(path string) {
	if runtime.GOOS != "windows" {
		return
	}
	actual, actualErr := filepath.Abs(path)
	expected, expectedErr := filepath.Abs(defaultMFADeviceFile())
	if actualErr == nil && expectedErr == nil && strings.EqualFold(actual, expected) {
		return
	}
	log.Printf("Warning: Windows does not enforce Unix 0600 modes; ensure MFA device file is in a user-private location: %s", path)
}

func generateMFABrowserFingerprint() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate MFA browser fingerprint: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(data)), nil
}

func normalizeMFABrowserFingerprint(fingerprint string) (string, error) {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))
	if len(fingerprint) != 32 {
		return "", errors.New("browser fingerprint must contain exactly 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return "", errors.New("browser fingerprint must contain exactly 32 hexadecimal characters")
	}
	return fingerprint, nil
}

func registerMFABrowserFingerprint(client *http.Client, service, fingerprint string) error {
	fingerprint, err := normalizeMFABrowserFingerprint(fingerprint)
	if err != nil {
		return err
	}

	endpoint, err := url.Parse(idsHost + "/authserver/bfp/info")
	if err != nil {
		return err
	}
	query := endpoint.Query()
	query.Set("bfp", fingerprint)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	loginURL := idsHost + "/authserver/login"
	if service != "" {
		loginURL += "?service=" + url.QueryEscape(service)
	}
	req.Header.Set("Referer", loginURL)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET bfp/info: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); err != nil {
		return fmt.Errorf("read bfp/info response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bfp/info returned %s", resp.Status)
	}

	cookieFingerprint, ok := cookieJarValue(client, endpoint, mfaBrowserFingerprintCookie)
	if !ok {
		return errors.New("bfp/info did not establish the browser fingerprint cookie")
	}
	if cookieFingerprint != fingerprint {
		return errors.New("bfp/info established a mismatched browser fingerprint cookie")
	}
	return nil
}

func cookieJarValue(client *http.Client, endpoint *url.URL, name string) (string, bool) {
	if client.Jar == nil {
		return "", false
	}
	for _, cookie := range client.Jar.Cookies(endpoint) {
		if cookie.Name == name {
			return cookie.Value, true
		}
	}
	return "", false
}
