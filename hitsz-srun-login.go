package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func main() {
	var username, password string
	flag.StringVar(&username, "username", "", "Username to login HIT SSO with")
	flag.StringVar(&password, "password", "", "Password to login HIT SSO with")
	flag.Parse()

	if username == "" || password == "" {
		flag.Usage()
		return
	}

	const srunServiceURL = "http://10.248.98.2/srun_portal_sso"
	callbackURL, err := authenticate(srunServiceURL, username, password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("SSO Authenticated.")

	ticket, err := parseTicket(srunServiceURL, callbackURL)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Ticket: " + ticket)

	result, err := netLogin(ticket)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Login Result: " + result)
}

func authenticate(service, username, password string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), service) {
				return http.ErrUseLastResponse
			} else {
				return nil
			}
		},
	}

	// 1) GET 登录页
	loginURL := "https://ids.hit.edu.cn/authserver/login?service=" + url.QueryEscape(service)
	resp, err := client.Get(loginURL)
	if err != nil {
		return "", fmt.Errorf("GET login: %w", err)
	}
	defer resp.Body.Close()

	htmlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read login page: %w", err)
	}

	// 2) 解析隐藏字段（form#pwdFromId input[type=hidden]）
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(htmlBytes))
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

	// 3) 使用服务端返回的 salt 对密码进行加密
	if pwdSalt == "" {
		return "", errors.New("fail to get pwdEncryptSalt")
	}
	encPwd, err := aesEncryptPassword(password, pwdSalt)
	if err != nil {
		return "", fmt.Errorf("encrypt password: %w", err)
	}
	formData["password"] = encPwd

	// 4) 额外字段
	formData["captcha"] = ""
	formData["rememberMe"] = "true"

	// 5) POST 表单
	values := url.Values{}
	for k, v := range formData {
		values.Set(k, v)
	}

	postResp, err := client.PostForm(loginURL, values)
	if err != nil {
		return "", fmt.Errorf("POST login: %w", err)
	}
	defer postResp.Body.Close()

	// 凭据不正确或者需要验证码
	if postResp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("unexpected status code: %s, maybe credential is not correct or captcha is required", postResp.Status)
	}

	// 正常情况下应该是重定向
	finalURL, err := postResp.Location()
	if err != nil {
		return "", fmt.Errorf("POST location not found")
	}
	finalURLStr := finalURL.String()
	if !strings.HasPrefix(finalURLStr, service) {
		return "", fmt.Errorf("authentication failed, return url is %s", finalURL)
	}
	return finalURLStr, nil
}

func parseTicket(service, urlStr string) (string, error) {
	service += "?ticket="
	if !strings.HasPrefix(urlStr, service) {
		return "", errors.New("invalid ticket url")
	}
	return strings.TrimPrefix(urlStr, service), nil
}

func netLogin(ticket string) (string, error) {
	srunLoginURL := "https://net.hitsz.edu.cn/v1/srun_portal_sso?ticket=" + ticket
	resp, err := http.Get(srunLoginURL)
	if err != nil {
		return "", fmt.Errorf("GET srun login: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read srun login page: %w", err)
	}

	return string(body), nil
}

func aesEncryptPassword(password, salt string) (string, error) {
	// if salt is empty, return plain password
	if len(salt) == 0 {
		return password, nil
	}
	if len(salt) != 16 {
		return "", errors.New("salt length NOT equals 16")
	}

	// 生成随机 IV（16 个可打印字符）和随机前缀（64 个可打印字符）
	iv, err := randomString(16)
	if err != nil {
		return "", fmt.Errorf("gen iv: %w", err)
	}
	prefix, err := randomString(64)
	if err != nil {
		return "", fmt.Errorf("gen prefix: %w", err)
	}

	// data = prefix || password
	data := append([]byte(prefix), []byte(password)...)

	// AES-128-CBC with PKCS7 padding
	block, err := aes.NewCipher([]byte(salt)) // salt 直接作为 16 字节 key
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	padded := pkcs7Pad(data, aes.BlockSize)
	ciphertext := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, []byte(iv)) // IV 就是上面 16 字符串的字节
	mode.CryptBlocks(ciphertext, padded)

	// Base64 标准编码返回（不携带 IV，与 Rust 保持一致）
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

const aesChars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

func randomString(n int) (string, error) {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(aesChars))))
		if err != nil {
			return "", err
		}
		b[i] = aesChars[num.Int64()]
	}
	return string(b), nil
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - (len(b) % blockSize)
	p := make([]byte, pad)
	for i := 0; i < pad; i++ {
		p[i] = byte(pad)
	}
	return append(b, p...)
}
