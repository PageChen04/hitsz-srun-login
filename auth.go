package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const srunServiceURL = "http://10.248.98.2/srun_portal_sso"

type authOptions struct {
	MFAMethod      string
	MFACode        string
	NonInteractive bool
	Stdin          io.Reader
	Stdout         io.Writer
}

func authenticate(service, username, password string, client *http.Client, opts authOptions) (string, error) {
	prevCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), service) || isMFAURL(req.URL.String()) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	defer func() { client.CheckRedirect = prevCheckRedirect }()

	loginURL := "https://ids.hit.edu.cn/authserver/login?service=" + url.QueryEscape(service)
	resp, err := client.Get(loginURL)
	if err != nil {
		return "", fmt.Errorf("GET login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		callbackURL, err := resp.Location()
		if err != nil {
			return "", fmt.Errorf("GET location not found")
		}
		callbackURLStr := callbackURL.String()
		if strings.HasPrefix(callbackURLStr, service) {
			return callbackURLStr, nil
		}
		return "", fmt.Errorf("unexpected redirect target: %s", callbackURLStr)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected login page status: %s", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("parse document: %w", err)
	}

	formData := make(map[string]string)
	formData["username"] = username
	formData["password"] = password

	var pwdSalt string
	doc.Find("form#pwdFromId input[type='hidden']").Each(func(_ int, sel *goquery.Selection) {
		name, _ := sel.Attr("name")
		val, _ := sel.Attr("value")

		if name != "" && val != "" {
			formData[name] = val
			if name == "pwdEncryptSalt" {
				pwdSalt = val
			}
			return
		}
		if id, ok := sel.Attr("id"); ok && id == "pwdEncryptSalt" {
			if v, ok := sel.Attr("value"); ok {
				pwdSalt = v
			}
		}
	})

	if pwdSalt == "" {
		return "", errors.New("fail to get pwdEncryptSalt")
	}
	encPwd, err := aesEncryptPassword(password, pwdSalt)
	if err != nil {
		return "", fmt.Errorf("fail to encrypt password: %w", err)
	}
	formData["password"] = encPwd
	formData["captcha"] = ""
	formData["rememberMe"] = "true"

	values := url.Values{}
	for k, v := range formData {
		values.Set(k, v)
	}

	postResp, err := client.PostForm(loginURL, values)
	if err != nil {
		return "", fmt.Errorf("POST login: %w", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusFound {
		body, err := io.ReadAll(postResp.Body)
		if err != nil {
			return "", fmt.Errorf("read login response: %w", err)
		}
		if isMFAPage(postResp.Request.URL.String(), string(body)) {
			return completeMFA(client, mfaContext{Service: service}, username, string(body), opts)
		}
		return "", fmt.Errorf("unexpected status code: %s, maybe credential is not correct or captcha is required", postResp.Status)
	}

	callbackURL, err := postResp.Location()
	if err != nil {
		return "", fmt.Errorf("POST location not found")
	}
	callbackURLStr := callbackURL.String()
	if isMFAURL(callbackURLStr) {
		body, err := io.ReadAll(postResp.Body)
		if err != nil {
			return "", fmt.Errorf("read mfa response: %w", err)
		}
		return completeMFA(client, mfaContext{Service: service}, username, string(body), opts)
	}
	if !strings.HasPrefix(callbackURLStr, service) {
		return "", fmt.Errorf("authentication failed, return url is %s", callbackURL)
	}
	return callbackURLStr, nil
}

func parseTicket(service, urlStr string) (string, error) {
	service += "?ticket="
	if !strings.HasPrefix(urlStr, service) {
		return "", errors.New("invalid ticket url")
	}
	return strings.TrimPrefix(urlStr, service), nil
}
