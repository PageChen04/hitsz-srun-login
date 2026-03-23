package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	totpPeriod = 30
	totpDigits = 6
)

func generateTOTP(secret string) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if normalized == "" {
		return "", fmt.Errorf("empty otp secret")
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("decode otp secret: %w", err)
	}

	counter := uint64(time.Now().Unix() / totpPeriod)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(counterBytes[:]); err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (int(sum[offset])&0x7f)<<24 |
		int(sum[offset+1])<<16 |
		int(sum[offset+2])<<8 |
		int(sum[offset+3])

	modulus := 1
	for i := 0; i < totpDigits; i++ {
		modulus *= 10
	}
	code %= modulus

	return fmt.Sprintf("%0*d", totpDigits, code), nil
}
