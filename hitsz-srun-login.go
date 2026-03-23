package main

import (
	"bufio"
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
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	var username, password, bind, sessionFile, mfaMethod, mfaCode, otpSecret string
	var dryRun, noSession, nonInteractive bool
	input := bufio.NewReader(os.Stdin)
	flag.StringVar(&username, "username", "", "Username to login HIT SSO with")
	flag.StringVar(&password, "password", "", "Password to login HIT SSO with")
	flag.StringVar(&bind, "bind", "", "IP to bind to")
	flag.BoolVar(&dryRun, "dry-run", false, "Only login HIT SSO without final campus network login")
	flag.StringVar(&sessionFile, "session-file", defaultSessionFile(), "Path to persisted session cookies")
	flag.BoolVar(&noSession, "no-session", false, "Disable loading and saving persisted session cookies")
	flag.BoolVar(&nonInteractive, "non-interactive", false, "Fail instead of prompting for missing values")
	flag.StringVar(&mfaMethod, "mfa-method", "", "Preferred MFA method: sms, app, email, otp")
	flag.StringVar(&mfaCode, "mfa-code", "", "MFA verification code or OTP; if empty, prompt interactively when needed")
	flag.StringVar(&otpSecret, "otp-secret", "", "TOTP secret used to generate OTP locally when -mfa-method otp and -mfa-code is empty")
	flag.Parse()

	var err error
	if username == "" {
		username, err = promptInput(input, os.Stdout, "username: ", "username", nonInteractive)
		if err != nil {
			log.Fatal("Failed to read username: ", err)
		}
	}
	if password == "" {
		password, err = promptInput(input, os.Stdout, "password: ", "password", nonInteractive)
		if err != nil {
			log.Fatal("Failed to read password: ", err)
		}
	}

	if noSession {
		sessionFile = ""
	} else {
		log.Printf("Session file: %s", sessionFile)
	}

	client, jar := newHttpClient(bind, sessionFile)
	defer func() {
		if err := jar.Save(); err != nil {
			log.Printf("Save session: %v", err)
		}
	}()

	callbackURL, err := authenticate(srunServiceURL, username, password, client, authOptions{
		MFAMethod:      mfaMethod,
		MFACode:        mfaCode,
		OTPSecret:      otpSecret,
		NonInteractive: nonInteractive,
		Stdin:          input,
		Stdout:         os.Stdout,
	})
	if err != nil {
		log.Fatal("Failed to authenticate: ", err)
	}
	log.Print("SSO Authenticated.")

	ticket, err := parseTicket(srunServiceURL, callbackURL)
	if err != nil {
		log.Fatal("Failed to parse ticket: ", err)
	}
	log.Printf("Ticket: %s", ticket)
	if dryRun {
		log.Print("Dry run enabled, skip final campus network login.")
		return
	}

	result, err := netLogin(ticket, client)
	if err != nil {
		log.Fatal("Failed to login to campus network: ", err)
	}
	log.Printf("Login Result: %s", result)
}

func promptInput(stdin *bufio.Reader, stdout io.Writer, prompt, field string, nonInteractive bool) (string, error) {
	if nonInteractive {
		return "", fmt.Errorf("missing %s in non-interactive mode", field)
	}
	for {
		if stdout != nil {
			fmt.Fprint(stdout, prompt)
		}
		line, err := stdin.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("stdin eof while reading %s", field)
			}
			return "", err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
}

func newHttpClient(bindIP, sessionFile string) (*http.Client, *persistentCookieJar) {
	jar, err := newPersistentCookieJar(sessionFile)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
	}
	if bindIP != "" {
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(bindIP)}}
		transport := &http.Transport{DialContext: dialer.DialContext}
		client.Transport = transport
	}
	return client, jar
}

func netLogin(ticket string, client *http.Client) (string, error) {
	srunLoginURL := "https://net.hitsz.edu.cn/v1/srun_portal_sso?ticket=" + ticket
	resp, err := client.Get(srunLoginURL)
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
	if len(salt) == 0 {
		return password, nil
	}
	if len(salt) != 16 {
		return "", errors.New("salt length NOT equals 16")
	}

	iv, err := randomString(16)
	if err != nil {
		return "", fmt.Errorf("gen iv: %w", err)
	}
	prefix, err := randomString(64)
	if err != nil {
		return "", fmt.Errorf("gen prefix: %w", err)
	}

	data := append([]byte(prefix), []byte(password)...)

	// AES-128-CBC with PKCS7 padding
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	padded := pkcs7Pad(data, aes.BlockSize)
	ciphertext := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, padded)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func randomString(n int) (string, error) {
	const aesChars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
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
