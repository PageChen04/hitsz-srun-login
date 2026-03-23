package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const idsHost = "https://ids.hit.edu.cn"

type mfaMethod struct {
	Key              string
	ReauthType       int
	AuthCodeTypeName string
	NeedsDynamicCode bool
}

type mfaContext struct {
	Service string
}

var defaultMFAMethods = []mfaMethod{
	{Key: "sms", ReauthType: 3, AuthCodeTypeName: "reAuthDynamicCodeType", NeedsDynamicCode: true},
	{Key: "app", ReauthType: 13, AuthCodeTypeName: "reAuthWeLinkDynamicCodeType", NeedsDynamicCode: true},
	{Key: "email", ReauthType: 11, AuthCodeTypeName: "reAuthEmailDynamicCodeType", NeedsDynamicCode: true},
	{Key: "otp", ReauthType: 10, NeedsDynamicCode: false},
}

func (c mfaContext) reauthViewURL() string {
	base := idsHost + "/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true"
	if c.Service == "" {
		return base
	}
	return base + "&service=" + url.QueryEscape(c.Service)
}

func (c mfaContext) serviceFormValue() string {
	return c.Service
}

func completeMFA(client *http.Client, ctx mfaContext, username, pageBody string, opts authOptions) (string, error) {
	methods, err := availableMFAMethods(client, ctx, pageBody)
	if err != nil {
		return "", err
	}
	if len(methods) == 0 {
		return "", errors.New("mfa required but no supported methods found")
	}

	method, err := chooseMFAMethod(methods, opts)
	if err != nil {
		return "", err
	}

	if err := changeReauthType(client, ctx, method); err != nil {
		return "", err
	}
	if method.NeedsDynamicCode {
		msg, err := sendMFACode(client, ctx, username, method)
		if err != nil {
			return "", err
		}
		log.Print(msg)
	}

	code, err := resolveMFACode(method, opts)
	if err != nil {
		return "", err
	}
	if err := submitMFACode(client, ctx, code, method); err != nil {
		return "", err
	}
	return finalizeMFALogin(client, ctx)
}

func isMFAURL(rawURL string) bool {
	lowerURL := strings.ToLower(rawURL)
	return strings.Contains(lowerURL, "reauthloginview.do") || strings.Contains(lowerURL, "ismultifactor=true")
}

func isMFAPage(rawURL, body string) bool {
	if isMFAURL(rawURL) {
		return true
	}
	lowerBody := strings.ToLower(body)
	return strings.Contains(lowerBody, "reauthloginview.do") || strings.Contains(lowerBody, "ismultifactor=true")
}

func isAuthLoginPage(rawURL, body string) bool {
	lowerURL := strings.ToLower(rawURL)
	lowerBody := strings.ToLower(body)
	return strings.Contains(lowerURL, "/authserver/login") &&
		(strings.Contains(lowerBody, "#pwdfromid") ||
			strings.Contains(lowerBody, `id="pwdfromid"`) ||
			strings.Contains(lowerBody, "pwdencryptsalt"))
}

func availableMFAMethods(client *http.Client, ctx mfaContext, pageBody string) ([]mfaMethod, error) {
	methodIDs, err := parseMFATypeIDs(pageBody)
	if err != nil || len(methodIDs) == 0 {
		resp, refreshErr := client.Get(ctx.reauthViewURL())
		if refreshErr != nil {
			if err != nil {
				return nil, err
			}
			return nil, refreshErr
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, readErr
		}
		methodIDs, err = parseMFATypeIDs(string(body))
		if err != nil {
			return nil, err
		}
	}

	var methods []mfaMethod
	for _, methodID := range methodIDs {
		for _, method := range defaultMFAMethods {
			if strconv.Itoa(method.ReauthType) == methodID {
				methods = append(methods, method)
			}
		}
	}
	return methods, nil
}

func parseMFATypeIDs(html string) ([]string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var ids []string
	doc.Find(".changeReAuthTypes").Each(func(_ int, sel *goquery.Selection) {
		id, ok := sel.Attr("id")
		if !ok || id == "" {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	})
	return ids, nil
}

func chooseMFAMethod(methods []mfaMethod, opts authOptions) (mfaMethod, error) {
	if opts.MFAMethod != "" {
		key := strings.ToLower(strings.TrimSpace(opts.MFAMethod))
		for _, method := range methods {
			if method.Key == key {
				return method, nil
			}
		}
		return mfaMethod{}, fmt.Errorf("unsupported mfa method %q", opts.MFAMethod)
	}
	if opts.NonInteractive {
		return mfaMethod{}, errors.New("mfa method required in non-interactive mode")
	}
	if opts.Stdout != nil {
		var keys []string
		for _, method := range methods {
			keys = append(keys, method.Key)
		}
		fmt.Fprintf(opts.Stdout, "available mfa methods: %s\n", strings.Join(keys, " "))
	}
	reader := bufio.NewReader(opts.Stdin)
	for {
		if opts.Stdout != nil {
			fmt.Fprint(opts.Stdout, "mfa-method: ")
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return mfaMethod{}, errors.New("stdin eof while reading mfa method")
			}
			return mfaMethod{}, fmt.Errorf("read mfa method: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, method := range methods {
			if line == method.Key {
				return method, nil
			}
		}
		if opts.Stdout != nil {
			fmt.Fprintln(opts.Stdout, "invalid mfa method")
		}
	}
}

func changeReauthType(client *http.Client, ctx mfaContext, method mfaMethod) error {
	resp, err := postIDsForm(client, ctx, "/authserver/reAuthCheck/changeReAuthType.do", url.Values{
		"isMultifactor": {"true"},
		"reAuthType":    {strconv.Itoa(method.ReauthType)},
		"service":       {ctx.serviceFormValue()},
	}, true, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func sendMFACode(client *http.Client, ctx mfaContext, username string, method mfaMethod) (string, error) {
	if !method.NeedsDynamicCode {
		return "", nil
	}
	if strings.TrimSpace(username) == "" {
		return "", errors.New("missing username for mfa code delivery")
	}
	resp, err := postIDsForm(client, ctx, "/authserver/dynamicCode/getDynamicCodeByReauth.do", url.Values{
		"userName":         {strings.TrimSpace(username)},
		"authCodeTypeName": {method.AuthCodeTypeName},
	}, true, true)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return ensureDynamicCodeSent(resp)
}

func ensureDynamicCodeSent(resp *http.Response) (string, error) {
	if resp.StatusCode >= 400 {
		return "", errors.New("failed to send mfa code")
	}
	if sessionExpiredFromResponse(resp) {
		return "", errors.New("session expired, please login again")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		return "", errors.New("failed to send mfa code")
	}
	parsed := tryParseJSONObject(bodyText)
	if parsed == nil {
		return "", errors.New("failed to send mfa code")
	}
	if errCode, ok := parsed["errCode"].(string); ok && errCode == "206302" {
		return "", errors.New("session expired, please login again")
	}
	if success, ok := parsed["success"].(bool); ok {
		if success {
			return "MFA code sent.", nil
		}
		return "", errors.New(extractMessage(parsed))
	}
	if res, ok := parsed["res"].(string); ok {
		if strings.EqualFold(res, "success") {
			return "MFA code sent.", nil
		}
		return "", errors.New(extractMessage(parsed))
	}
	if code, ok := parsed["code"]; ok {
		switch value := code.(type) {
		case string:
			if value == "200" {
				return "MFA code sent.", nil
			}
		case float64:
			if value == 200 {
				return "MFA code sent.", nil
			}
		}
	}
	return "", errors.New("failed to send mfa code")
}

func resolveMFACode(method mfaMethod, opts authOptions) (string, error) {
	if code := strings.TrimSpace(opts.MFACode); code != "" {
		return code, nil
	}
	if opts.NonInteractive {
		return "", errors.New("mfa code required in non-interactive mode")
	}
	reader := bufio.NewReader(opts.Stdin)
	for {
		if opts.Stdout != nil {
			if method.NeedsDynamicCode {
				fmt.Fprint(opts.Stdout, "mfa-code: ")
			} else {
				fmt.Fprint(opts.Stdout, "otp: ")
			}
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if method.NeedsDynamicCode {
					return "", errors.New("stdin eof while reading mfa code")
				}
				return "", errors.New("stdin eof while reading otp")
			}
			return "", fmt.Errorf("read mfa code: %w", err)
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
}

func submitMFACode(client *http.Client, ctx mfaContext, code string, method mfaMethod) error {
	if strings.TrimSpace(code) == "" {
		return errors.New("empty mfa code")
	}
	values := url.Values{
		"service":       {ctx.serviceFormValue()},
		"reAuthType":    {strconv.Itoa(method.ReauthType)},
		"isMultifactor": {"true"},
		"password":      {""},
		"dynamicCode":   {""},
		"uuid":          {""},
		"answer1":       {""},
		"answer2":       {""},
		"otpCode":       {""},
		"skipTmpReAuth": {"true"},
	}
	if method.NeedsDynamicCode {
		values.Set("dynamicCode", strings.TrimSpace(code))
	} else {
		values.Set("otpCode", strings.TrimSpace(code))
	}

	resp, err := postIDsForm(client, ctx, "/authserver/reAuthCheck/reAuthSubmit.do", values, false, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !isSubmitSuccess(resp, ctx.Service) {
		return errors.New("mfa verification failed")
	}
	return nil
}

func finalizeMFALogin(client *http.Client, ctx mfaContext) (string, error) {
	prevCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if ctx.Service != "" && strings.HasPrefix(req.URL.String(), ctx.Service) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	defer func() { client.CheckRedirect = prevCheckRedirect }()

	reqURL := idsHost + "/authserver/login"
	if ctx.Service != "" {
		reqURL += "?service=" + url.QueryEscape(ctx.Service)
	}
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Referer", ctx.reauthViewURL())

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		location, err := resp.Location()
		if err != nil {
			return "", errors.New("mfa completed but callback location missing")
		}
		locationStr := location.String()
		if ctx.Service != "" && strings.HasPrefix(locationStr, ctx.Service) {
			return locationStr, nil
		}
		return "", fmt.Errorf("unexpected post-mfa redirect target: %s", locationStr)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	bodyText := string(body)
	if isMFAPage(resp.Request.URL.String(), bodyText) {
		return "", errors.New("mfa did not complete")
	}
	if isAuthLoginPage(resp.Request.URL.String(), bodyText) {
		return "", errors.New("session expired, please login again")
	}
	if ctx.Service != "" && strings.HasPrefix(resp.Request.URL.String(), ctx.Service) {
		return resp.Request.URL.String(), nil
	}
	return "", errors.New("unable to obtain service callback after mfa")
}

func postIDsForm(client *http.Client, ctx mfaContext, path string, form url.Values, asAjax, allowRedirects bool) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, idsHost+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", idsHost)
	req.Header.Set("Referer", ctx.reauthViewURL())
	if asAjax {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}

	if allowRedirects {
		return client.Do(req)
	}

	prevCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { client.CheckRedirect = prevCheckRedirect }()
	return client.Do(req)
}

func sessionExpiredFromResponse(resp *http.Response) bool {
	location := strings.ToLower(responseLocation(resp))
	return strings.Contains(strings.ToLower(resp.Request.URL.String()), "/authserver/login") || strings.Contains(location, "/authserver/login")
}

func responseLocation(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	location := resp.Header.Get("Location")
	return location
}

func isSubmitSuccess(resp *http.Response, service string) bool {
	location := responseLocation(resp)
	if service != "" && locationMatchesService(location, service) {
		return true
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		return false
	}
	if strings.Contains(strings.ToLower(bodyText), "reauth_success") {
		return true
	}
	parsed := tryParseJSONObject(bodyText)
	if parsed == nil {
		return false
	}
	if code, ok := parsed["code"].(string); ok && strings.EqualFold(code, "reauth_success") {
		return true
	}
	return false
}

func locationMatchesService(location, service string) bool {
	if location == "" {
		return false
	}
	if strings.HasPrefix(location, service) {
		return true
	}
	serviceURL, err := url.Parse(service)
	if err != nil {
		return false
	}
	locationURL, err := url.Parse(location)
	if err != nil {
		return false
	}
	if serviceURL.Scheme != "" && locationURL.Scheme != "" && serviceURL.Scheme != locationURL.Scheme {
		return false
	}
	if serviceURL.Host != "" && locationURL.Host != "" && serviceURL.Host != locationURL.Host {
		return false
	}
	if serviceURL.Path != "" && serviceURL.Path != locationURL.Path {
		return false
	}
	query := locationURL.Query()
	if _, ok := query["ticket"]; ok {
		return true
	}
	return serviceURL.Host != "" || serviceURL.Path != ""
}

func tryParseJSONObject(content string) map[string]any {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}
	return parsed
}

func extractMessage(data map[string]any) string {
	for _, key := range []string{"message", "returnMessage", "msg"} {
		if value, ok := data[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "operation failed"
}
