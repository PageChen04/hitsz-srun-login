package main

// Self-service portal (net.hitsz.edu.cn:8800) operations:
//   - Local login (CSRF + RSA + form POST)
//   - Scraping device list from /home
//   - Kicking a device (/home/delete)
//
// Srun portal (net.hitsz.edu.cn) operations:
//   - Local user network auth  (get_challenge → srun_portal login)
//   - Network logout           (rad_user_dm)
//   - User info / IP           (rad_user_info)

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	selfServiceBase = "https://net.hitsz.edu.cn:8800"
	srunPortalBase  = "https://net.hitsz.edu.cn"
	srunAcID        = "1"
	srunN           = "200"
	srunType        = "1"
	srunEnc         = "srun_bx1"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// OnlineDevice is a device currently authenticated on the campus network.
type OnlineDevice struct {
	RadOnlineID string
	Username    string
	IP          string
	MAC         string
	LoginTime   string
	Duration    string
	Product     string
}

// ---------------------------------------------------------------------------
// Self-service portal: local login
// ---------------------------------------------------------------------------

// selfServiceLogin logs in to the self-service portal (net.hitsz.edu.cn:8800)
// using a local username and password. The session cookie is stored in client.Jar.
// Returns the CSRF token of the resulting home page, or an error.
//
// The deployment requires a captcha for the form login: if the login page
// renders a captcha input, the image is downloaded to a temp file and its path
// is printed; captchaCode (from -captcha) is used if given, otherwise the user
// is prompted on stdout. Non-interactive mode fails instead of prompting — see
// resolveSelfServiceCaptcha for how -captcha interacts with the pending
// session (sessionFile).
func selfServiceLogin(username, password, captchaCode string, nonInteractive bool,
	stdin *bufio.Reader, stdout io.Writer, client *http.Client, sessionFile string) (string, error) {
	loginURL := selfServiceBase + "/"

	// Step 1: GET / — collect CSRF token and RSA public key.
	log.Printf("[portal] GET %s", loginURL)
	resp, err := client.Get(loginURL)
	if err != nil {
		return "", fmt.Errorf("GET self-service login page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET self-service login page: unexpected status %s", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("parse self-service login page: %w", err)
	}

	csrfToken, ok := doc.Find(`meta[name="csrf-token"]`).Attr("content")
	if !ok || csrfToken == "" {
		return "", fmt.Errorf("CSRF token not found on login page")
	}
	log.Printf("[portal] CSRF token: %s", csrfToken[:min(16, len(csrfToken))]+"...")

	pubKeyPEM, ok := doc.Find(`input#public`).Attr("value")
	if !ok || pubKeyPEM == "" {
		return "", fmt.Errorf("RSA public key not found on login page")
	}
	log.Printf("[portal] RSA public key found (%d bytes)", len(pubKeyPEM))

	// Captcha: only if the page renders a verify-code field (Yii2 Captcha widget).
	verifyCode := ""
	if doc.Find(`input[name="LoginForm[verifyCode]"]`).Length() > 0 {
		verifyCode, err = resolveSelfServiceCaptcha(captchaCode, nonInteractive, stdin, stdout, client, sessionFile)
		if err != nil {
			return "", err
		}
	}

	// Step 2: RSA-encrypt the password (portal uses JSEncrypt = RSA PKCS1v15).
	encryptedPassword, err := rsaEncryptPKCS1v15(pubKeyPEM, password)
	if err != nil {
		return "", fmt.Errorf("RSA encrypt password: %w", err)
	}
	log.Printf("[portal] Password RSA-encrypted")

	// Step 3: POST /site/validate-user — pre-validate (XHR).
	validateForm := url.Values{
		"LoginForm[username]":   {username},
		"LoginForm[password]":   {encryptedPassword},
		"LoginForm[verifyCode]": {verifyCode},
	}
	log.Printf("[portal] POST %s/site/validate-user", selfServiceBase)
	validateReq, err := http.NewRequest("POST", selfServiceBase+"/site/validate-user",
		strings.NewReader(validateForm.Encode()))
	if err != nil {
		return "", fmt.Errorf("build validate-user request: %w", err)
	}
	validateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	validateReq.Header.Set("X-Requested-With", "XMLHttpRequest")
	validateReq.Header.Set("X-CSRF-Token", csrfToken)

	validateResp, err := client.Do(validateReq)
	if err != nil {
		return "", fmt.Errorf("POST validate-user: %w", err)
	}
	defer validateResp.Body.Close()
	validateBody, _ := io.ReadAll(validateResp.Body)
	log.Printf("[portal] validate-user response (%d): %s", validateResp.StatusCode, string(validateBody))

	var validateResult struct {
		Success  bool   `json:"success"`
		InputSms bool   `json:"inputSms"`
		Message  string `json:"message"`
	}
	if err := json.Unmarshal(validateBody, &validateResult); err != nil {
		return "", fmt.Errorf("parse validate-user response: %w (body: %s)", err, string(validateBody))
	}
	if !validateResult.Success {
		msg := validateResult.Message
		if strings.Contains(msg, "验证码") || strings.Contains(msg, "verify") {
			clearCaptchaPending(sessionFile)
			msg += " (captcha codes are single-use; run once without -captcha to generate a fresh image)"
		}
		return "", fmt.Errorf("validate-user failed: %s", msg)
	}

	// Step 4: POST / — actual login form.
	loginForm := url.Values{
		"_csrf-8800":            {csrfToken},
		"LoginForm[username]":   {username},
		"LoginForm[password]":   {encryptedPassword},
		"LoginForm[smsCode]":    {""},
		"LoginForm[verifyCode]": {verifyCode},
	}
	log.Printf("[portal] POST %s/ (login form)", selfServiceBase)

	// We need to NOT follow the redirect here so we can inspect Set-Cookie.
	prevCheck := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	loginResp, err := client.Post(loginURL, "application/x-www-form-urlencoded",
		strings.NewReader(loginForm.Encode()))
	client.CheckRedirect = prevCheck
	if err != nil {
		return "", fmt.Errorf("POST login form: %w", err)
	}
	defer loginResp.Body.Close()
	log.Printf("[portal] login form response: %s, Location: %s",
		loginResp.Status, loginResp.Header.Get("Location"))

	if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		return "", fmt.Errorf("login form unexpected status %s (body: %.200s)", loginResp.Status, string(body))
	}

	// Follow redirect to /home manually (client.Jar already has the session cookie).
	location := loginResp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("login form redirect has no Location header")
	}
	if !strings.HasPrefix(location, "http") {
		location = selfServiceBase + "/" + strings.TrimPrefix(location, "/")
	}

	log.Printf("[portal] GET %s (post-login redirect)", location)
	homeResp, err := client.Get(location)
	if err != nil {
		return "", fmt.Errorf("GET home after login: %w", err)
	}
	defer homeResp.Body.Close()
	if homeResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET home: unexpected status %s", homeResp.Status)
	}

	homeDoc, err := goquery.NewDocumentFromReader(homeResp.Body)
	if err != nil {
		return "", fmt.Errorf("parse home page: %w", err)
	}
	homeCsrf, _ := homeDoc.Find(`meta[name="csrf-token"]`).Attr("content")
	log.Printf("[portal] logged in, home CSRF: %s", homeCsrf[:min(16, len(homeCsrf))]+"...")
	clearCaptchaPending(sessionFile)
	return homeCsrf, nil
}

// resolveSelfServiceCaptcha obtains the code required by the self-service
// login captcha.
//
// The captcha code is bound to the server-side session (PHPSESSID): fetching
// /site/captcha generates a fresh code and stores it in that session, and the
// code is single-use. A non-interactive run therefore cannot both fetch the
// image and use a code typed in a later process. Instead:
//
//   - Run without -captcha: the image is downloaded, saved to a temp file,
//     and the session cookies are persisted (jar.Save by the caller) together
//     with a pending-captcha marker so a follow-up run can reuse the SAME
//     session — and thus the SAME code — without re-fetching the image.
//   - Run with -captcha: the pending marker is checked and the code is used
//     as-is; /site/captcha is NOT fetched again, which would invalidate it.
//
// In interactive mode the code is read from stdin within the same process, so
// no pending state is needed.
func resolveSelfServiceCaptcha(captchaCode string, nonInteractive bool,
	stdin *bufio.Reader, stdout io.Writer, client *http.Client, sessionFile string) (string, error) {
	if captchaCode != "" {
		if sessionFile == "" {
			return "", fmt.Errorf("-captcha needs the persisted pending session; retry without -no-session")
		}
		if err := checkCaptchaPending(sessionFile); err != nil {
			return "", err
		}
		clearCaptchaPending(sessionFile)
		log.Printf("[portal] Using captcha from -captcha: %s (pending session reused)", captchaCode)
		return captchaCode, nil
	}

	resp, err := client.Get(selfServiceBase + "/site/captcha")
	if err != nil {
		return "", fmt.Errorf("GET captcha: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET captcha: unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read captcha image: %w", err)
	}
	if len(body) < 100 {
		return "", fmt.Errorf("captcha image too small (%d bytes)", len(body))
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("hitsz-srun-captcha-%d.png", time.Now().UnixNano()))
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", fmt.Errorf("save captcha image: %w", err)
	}

	if nonInteractive {
		if sessionFile != "" {
			// Persist the pending state: the caller saves the session cookies
			// (jar.Save) so a follow-up run with -captcha reuses this session
			// and this very code.
			if err := writeCaptchaPending(sessionFile, path); err != nil {
				return "", err
			}
			return "", fmt.Errorf("self-service login requires a captcha: open %s, then re-run the same command with -captcha <code> (pending session saved)", path)
		}
		return "", fmt.Errorf("self-service login requires a captcha: open %s, then re-run with -captcha <code>; note that -no-session prevents reusing the pending session", path)
	}

	log.Printf("[portal] Captcha image saved to %s", path)
	for {
		fmt.Fprintf(stdout, "captcha (see %s): ", path)
		line, err := stdin.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("stdin eof while reading captcha: %w", err)
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
}

// captchaPendingTTL bounds how long a pending captcha (session + image) stays
// usable; the portal's Yii2 captcha expires after 300 seconds.
const captchaPendingTTL = 5 * time.Minute

type captchaPending struct {
	Image   string `json:"image"`
	Created int64  `json:"created"`
}

// captchaMarkerPath returns the sidecar file that records a pending captcha
// for the given session file.
func captchaMarkerPath(sessionFile string) string {
	return sessionFile + ".captcha"
}

// writeCaptchaPending records the pending captcha image for a follow-up
// -captcha run.
func writeCaptchaPending(sessionFile, imagePath string) error {
	data, err := json.Marshal(captchaPending{Image: imagePath, Created: time.Now().Unix()})
	if err != nil {
		return fmt.Errorf("encode pending captcha: %w", err)
	}
	if err := os.WriteFile(captchaMarkerPath(sessionFile), data, 0o600); err != nil {
		return fmt.Errorf("save pending captcha marker: %w", err)
	}
	return nil
}

// checkCaptchaPending verifies a pending captcha exists and has not expired.
func checkCaptchaPending(sessionFile string) error {
	data, err := os.ReadFile(captchaMarkerPath(sessionFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no pending captcha; run the command once without -captcha to generate a captcha image first")
		}
		return fmt.Errorf("read pending captcha marker: %w", err)
	}
	var pending captchaPending
	if err := json.Unmarshal(data, &pending); err != nil {
		return fmt.Errorf("decode pending captcha marker: %w", err)
	}
	if time.Since(time.Unix(pending.Created, 0)) > captchaPendingTTL {
		clearCaptchaPending(sessionFile)
		return fmt.Errorf("pending captcha expired; run the command again without -captcha to get a fresh image")
	}
	log.Printf("[portal] Pending captcha from %s", pending.Image)
	return nil
}

// clearCaptchaPending removes the pending-captcha marker, if any.
func clearCaptchaPending(sessionFile string) {
	if sessionFile != "" {
		os.Remove(captchaMarkerPath(sessionFile))
	}
}

// tryExistingPortalSession attempts to access /home directly.
// Returns (csrfToken, true, nil) if already logged in, ("", false, nil) if not.
func tryExistingPortalSession(client *http.Client) (string, bool, error) {
	prevCheck := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(selfServiceBase + "/home")
	client.CheckRedirect = prevCheck
	if err != nil {
		return "", false, fmt.Errorf("GET /home: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		log.Printf("[portal] /home redirected to %s (not logged in)", loc)
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GET /home: unexpected status %s", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", false, fmt.Errorf("parse /home: %w", err)
	}
	csrf, _ := doc.Find(`meta[name="csrf-token"]`).Attr("content")
	log.Printf("[portal] existing session valid, CSRF: %s", csrf[:min(16, len(csrf))]+"...")
	return csrf, true, nil
}

// tryPortalSSO enters the self-service portal through the main portal's
// "Self Service" jump (/site/sso), mirroring Portal.js toSelfService().
// It needs no password when the current IP is already authenticated on the
// campus network: rad_user_info reports ok, and the self-service server
// creates a session for that account directly.
//
// Returns (csrfToken, true, nil) on success; ("", false, nil) when the main
// portal is not logged in (caller should fall back to credentials); or an
// error on transport/parse failures.
func tryPortalSSO(client *http.Client) (string, bool, error) {
	info, err := srunGetUserInfo("", client)
	if err != nil {
		return "", false, fmt.Errorf("rad_user_info: %w", err)
	}
	if info.Error != "ok" || info.Username == "" {
		log.Printf("[portal] main portal not logged in (error=%q), skip SSO jump", info.Error)
		return "", false, nil
	}

	// Portal.js: when online, data = lang + ":" + username, standard base64.
	data := base64.StdEncoding.EncodeToString([]byte("en-US:" + info.Username))
	ssoURL := selfServiceBase + "/site/sso?data=" + url.QueryEscape(data)
	log.Printf("[portal] GET %s (SSO jump for %s)", ssoURL, info.Username)

	resp, err := client.Get(ssoURL)
	if err != nil {
		return "", false, fmt.Errorf("GET /site/sso: %w", err)
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if !strings.HasPrefix(finalURL, selfServiceBase+"/home") {
		log.Printf("[portal] SSO jump did not reach /home (final: %s)", finalURL)
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("SSO jump /home: unexpected status %s", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", false, fmt.Errorf("parse SSO /home: %w", err)
	}
	csrf, _ := doc.Find(`meta[name="csrf-token"]`).Attr("content")
	if csrf == "" {
		return "", false, fmt.Errorf("CSRF token not found after SSO jump")
	}
	log.Printf("[portal] SSO jump succeeded for %s, CSRF: %s", info.Username, csrf[:min(16, len(csrf))]+"...")
	return csrf, true, nil
}

// ---------------------------------------------------------------------------
// Self-service portal: device list
// ---------------------------------------------------------------------------

// listOnlineDevices fetches /home and returns the device table.
// Expects an already-authenticated client.
func listOnlineDevices(client *http.Client) ([]OnlineDevice, error) {
	log.Printf("[portal] GET %s/home", selfServiceBase)
	resp, err := client.Get(selfServiceBase + "/home")
	if err != nil {
		return nil, fmt.Errorf("GET /home: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /home: unexpected status %s", resp.Status)
	}
	return parseDeviceTable(resp.Body)
}

// parseDeviceTable extracts the device table from the /home HTML body.
// /home renders a device table plus other tables (e.g. account product
// info); only rows carrying a /home/delete link (the Operating column) are
// devices.
func parseDeviceTable(r io.Reader) ([]OnlineDevice, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("parse /home HTML: %w", err)
	}

	var devices []OnlineDevice
	doc.Find("table tbody tr").Each(func(_ int, tr *goquery.Selection) {
		if tr.Find(`a[href*="/home/delete"]`).Length() == 0 {
			return // product-info or other table row, not an online device
		}
		tds := tr.Find("td")
		if tds.Length() < 6 {
			return
		}
		id, _ := tr.Attr("data-key")
		d := OnlineDevice{
			RadOnlineID: id,
			Username:    strings.TrimSpace(tds.Eq(0).Text()),
			IP:          strings.TrimSpace(tds.Eq(1).Text()),
			LoginTime:   strings.TrimSpace(tds.Eq(2).Text()),
			Duration:    strings.TrimSpace(tds.Eq(3).Text()),
			Product:     strings.TrimSpace(tds.Eq(4).Text()),
			MAC:         strings.TrimSpace(tds.Eq(5).Text()),
		}
		devices = append(devices, d)
	})
	return devices, nil
}

// ---------------------------------------------------------------------------
// Self-service portal: kick device
// ---------------------------------------------------------------------------

// kickDevice sends a POST /home/delete request for a device.
// id and mac come from the device table (RadOnlineID and MAC).
// csrfToken must be valid for the current session (from /home page).
func kickDevice(id, mac, csrfToken string, client *http.Client) error {
	targetURL := fmt.Sprintf("%s/home/delete?id=%s&user_mac=%s",
		selfServiceBase, id, url.QueryEscape(mac))
	log.Printf("[portal] POST %s", targetURL)

	form := url.Values{"_csrf-8800": {csrfToken}}

	prevCheck := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Post(targetURL, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	client.CheckRedirect = prevCheck
	if err != nil {
		return fmt.Errorf("POST /home/delete: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("[portal] kick response: %s (body: %.200s)", resp.Status, string(body))

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kick device: unexpected status %s", resp.Status)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Srun portal: user info (rad_user_info)
// ---------------------------------------------------------------------------

// SrunUserInfo holds online state queried from rad_user_info.
type SrunUserInfo struct {
	Error    string `json:"error"`
	Username string `json:"user_name"`
	IP       string `json:"online_ip"`
	ClientIP string `json:"client_ip"`
}

// srunGetUserInfo queries rad_user_info for the given IP.
// Returns (info, nil) where info.Error == "ok" means online.
func srunGetUserInfo(ip string, client *http.Client) (*SrunUserInfo, error) {
	cb := jsonpCallback()
	apiURL := fmt.Sprintf("%s/cgi-bin/rad_user_info?callback=%s&ip=%s&_=%d",
		srunPortalBase, cb, url.QueryEscape(ip), time.Now().UnixMilli())
	log.Printf("[srun] GET %s", apiURL)

	body, err := jsonpGet(client, apiURL)
	if err != nil {
		return nil, fmt.Errorf("rad_user_info: %w", err)
	}
	log.Printf("[srun] rad_user_info response: %.300s", string(body))

	var info SrunUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse rad_user_info: %w (body: %s)", err, string(body))
	}
	return &info, nil
}

// ---------------------------------------------------------------------------
// Srun portal: local network auth
// ---------------------------------------------------------------------------

// SrunLocalLoginResult is the parsed response from /cgi-bin/srun_portal.
type SrunLocalLoginResult struct {
	Error   string `json:"error"`
	ECode   int    `json:"ecode"`
	SucMsg  string `json:"suc_msg"`
	PloyMsg string `json:"ploy_msg"`
	Online  string `json:"online_ip"`
}

// srunLocalLogin performs local-user network authentication via the srun portal.
// ip is the IP to authenticate (may be empty → portal determines from request source).
func srunLocalLogin(username, password, ip string, client *http.Client) (*SrunLocalLoginResult, error) {
	// Step 1: get_challenge → token
	token, err := srunGetChallenge(username, ip, client)
	if err != nil {
		return nil, err
	}
	log.Printf("[srun] challenge token: %s", token)

	// Step 2: compute {MD5} password
	hmd5 := srunMD5Password(token, password)
	log.Printf("[srun] MD5 password hash computed")

	// Step 3: encode user info
	info, err := encodeUserInfo(username, password, ip, srunAcID, srunEnc, token)
	if err != nil {
		return nil, fmt.Errorf("encode user info: %w", err)
	}
	log.Printf("[srun] user info encoded: %s", info[:min(40, len(info))]+"...")

	// Step 4: compute chksum
	chksum := srunLoginChksum(token, username, hmd5, srunAcID, ip, srunN, srunType, info)
	log.Printf("[srun] chksum: %s", chksum)

	// Step 5: call srun_portal
	cb := jsonpCallback()
	params := url.Values{
		"callback":     {cb},
		"action":       {"login"},
		"username":     {username},
		"password":     {"{MD5}" + hmd5},
		"nas_ip":       {""},
		"double_stack": {"0"},
		"chksum":       {chksum},
		"info":         {info},
		"ac_id":        {srunAcID},
		"ip":           {ip},
		"n":            {srunN},
		"type":         {srunType},
		"captchaVal":   {""},
		"_":            {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	}
	apiURL := fmt.Sprintf("%s/cgi-bin/srun_portal?%s", srunPortalBase, params.Encode())
	log.Printf("[srun] GET srun_portal (login)")

	body, err := jsonpGet(client, apiURL)
	if err != nil {
		return nil, fmt.Errorf("srun_portal login: %w", err)
	}
	log.Printf("[srun] srun_portal response: %.500s", string(body))

	var result SrunLocalLoginResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse srun_portal response: %w (body: %s)", err, string(body))
	}
	return &result, nil
}

// srunGetChallenge fetches get_challenge and returns the challenge token.
func srunGetChallenge(username, ip string, client *http.Client) (string, error) {
	cb := jsonpCallback()
	apiURL := fmt.Sprintf("%s/cgi-bin/get_challenge?callback=%s&username=%s&ip=%s&_=%d",
		srunPortalBase, cb, url.QueryEscape(username), url.QueryEscape(ip), time.Now().UnixMilli())
	log.Printf("[srun] GET get_challenge")

	body, err := jsonpGet(client, apiURL)
	if err != nil {
		return "", fmt.Errorf("get_challenge: %w", err)
	}
	log.Printf("[srun] get_challenge response: %.300s", string(body))

	var result struct {
		Challenge string `json:"challenge"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse get_challenge: %w (body: %s)", err, string(body))
	}
	if result.Error != "ok" && result.Challenge == "" {
		return "", fmt.Errorf("get_challenge error: %s", result.Error)
	}
	return result.Challenge, nil
}

// ---------------------------------------------------------------------------
// Srun portal: logout (rad_user_dm)
// ---------------------------------------------------------------------------

// SrunLogoutResult is the parsed rad_user_dm response.
type SrunLogoutResult struct {
	Error  string `json:"error"`
	ECode  int    `json:"ecode"`
	SucMsg string `json:"suc_msg"`
}

// srunLogout sends the DM logout request for the given IP and username.
func srunLogout(username, ip string, client *http.Client) (*SrunLogoutResult, error) {
	now := time.Now().Unix()
	timeStr := strconv.FormatInt(now, 10)
	sign := srunLogoutSign(timeStr, username, ip)
	cb := jsonpCallback()

	params := url.Values{
		"callback": {cb},
		"user_ip":  {ip},
		"username": {username},
		"time":     {timeStr},
		"unbind":   {"1"},
		"sign":     {sign},
		"_":        {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	}
	apiURL := fmt.Sprintf("%s/cgi-bin/rad_user_dm?%s", srunPortalBase, params.Encode())
	log.Printf("[srun] GET rad_user_dm (logout) sign=%s", sign)

	body, err := jsonpGet(client, apiURL)
	if err != nil {
		return nil, fmt.Errorf("rad_user_dm: %w", err)
	}
	log.Printf("[srun] rad_user_dm response: %.300s", string(body))

	// rad_user_dm may return "{}" or a full object
	var result SrunLogoutResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse rad_user_dm: %w (body: %s)", err, string(body))
	}
	return &result, nil
}

// ---------------------------------------------------------------------------
// RSA helpers
// ---------------------------------------------------------------------------

// rsaEncryptPKCS1v15 encrypts data with the PEM-encoded public key using PKCS1v15.
// The portal login page uses JSEncrypt, which is PKCS1v15.
func rsaEncryptPKCS1v15(pubKeyPEM, plaintext string) (string, error) {
	pub, err := parseRSAPublicKey(pubKeyPEM)
	if err != nil {
		return "", err
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("RSA PKCS1v15 encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}

// ---------------------------------------------------------------------------
// JSONP helper
// ---------------------------------------------------------------------------

var jsonpRe = regexp.MustCompile(`^[^(]+\(([\s\S]*)\)\s*$`)

// jsonpGet fetches a JSONP URL and returns the JSON payload bytes.
func jsonpGet(client *http.Client, rawURL string) ([]byte, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	s := strings.TrimSpace(string(body))
	m := jsonpRe.FindStringSubmatch(s)
	if m == nil {
		// Try interpreting as plain JSON
		return []byte(s), nil
	}
	return []byte(m[1]), nil
}

// jsonpCallback returns a stable callback name (not random; avoids _ timestamp pollution).
func jsonpCallback() string {
	return "cb"
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
