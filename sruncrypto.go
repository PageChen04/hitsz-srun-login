package main

// srun portal crypto helpers:
//   - XXTEA + custom-base64 for the `info` field (encodeUserInfo)
//   - HMAC-MD5 style password hash used by srun (`{MD5}` prefix)
//   - SHA-1 logout sign

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// srunBase64Alpha is the custom base64 alphabet used by the portal.
const srunBase64Alpha = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

// encodeUserInfo encodes the user info struct into the `{SRBX1}...` string
// expected by the srun portal `info` parameter.
//
// Algorithm (mirrors Portal.js _encodeUserInfo):
//  1. Marshal info to JSON
//  2. XXTEA-encrypt(json, token)   [little-endian uint32 packing, length-appended]
//  3. Custom-base64-encode the raw bytes
//  4. Prepend "{SRBX1}"
func encodeUserInfo(username, password, ip string, acidStr, enc string, token string) (string, error) {
	infoJSON, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
		"ip":       ip,
		"acid":     acidStr,
		"enc_ver":  enc,
	})
	if err != nil {
		return "", err
	}

	encrypted := xxteaEncryptBytes(infoJSON, token)
	encoded := srunBase64Encode(encrypted)
	return "{SRBX1}" + encoded, nil
}

// xxteaEncryptBytes encrypts a string with a string key using XXTEA, then returns
// the cipher bytes (raw, not base64). Mirrors the JS `encode(str, key)`.
func xxteaEncryptBytes(str []byte, key string) []byte {
	if len(str) == 0 {
		return nil
	}
	v := bytesToUint32s(str, true)
	k := bytesToUint32s([]byte(key), false)
	if len(k) < 4 {
		k = k[:cap(append(k, make([]uint32, 4-len(k))...))]
		k = k[:4]
	}
	xxteaEncryptInPlace(v, k)
	return uint32sToBytes(v, false)
}

// xxteaEncryptInPlace performs the XXTEA cipher on v in-place.
//
// NOTE: this follows the mix variant shipped in the campus portal's
// Portal.js (srun 1.10.1), which computes
//
//	m = (z>>>5 ^ y<<2) + ((y>>>3 ^ z<<4) ^ (d ^ y)) + (k[p&3^e] ^ z)
//
// instead of the canonical XXTEA `((z>>>5^y<<2)+(y>>>3^z<<4)) ^ ((d^y)+(k^z))`.
// The two only agree for degenerate inputs; using the canonical form makes the
// server fail to decrypt `info`.
func xxteaEncryptInPlace(v, k []uint32) {
	n := len(v) - 1
	if n < 0 {
		return
	}
	z := v[n]
	y := v[0]
	c := uint32(0x86014019 | 0x183639A0) // = 0x9E3779B9 = xxteaDelta
	var d uint32
	q := 6 + 52/uint32(n+1)
	for ; q > 0; q-- {
		d = d + c
		e := (d >> 2) & 3
		var p int
		for p = 0; p < n; p++ {
			y = v[p+1]
			m := (z>>5 ^ y<<2) + ((y>>3 ^ z<<4) ^ (d ^ y)) + (k[uint32(p)&3^e] ^ z)
			v[p] = v[p] + m
			z = v[p]
		}
		y = v[0]
		m := (z>>5 ^ y<<2) + ((y>>3 ^ z<<4) ^ (d ^ y)) + (k[uint32(p)&3^e] ^ z)
		v[n] = v[n] + m
		z = v[n]
	}
}

// bytesToUint32s converts a string to a []uint32 using little-endian byte packing.
// If appendLen is true, appends the original byte length as the last element.
// Mirrors JS function s(a, b).
func bytesToUint32s(b []byte, appendLen bool) []uint32 {
	c := len(b)
	size := (c + 3) / 4
	if appendLen {
		size++
	}
	v := make([]uint32, size)
	for i := 0; i < c; i += 4 {
		var word uint32
		for j := 0; j < 4 && i+j < c; j++ {
			word |= uint32(b[i+j]) << (uint(j) * 8)
		}
		v[i/4] = word
	}
	if appendLen {
		v[len(v)-1] = uint32(c)
	}
	return v
}

// uint32sToBytes converts []uint32 back to bytes using little-endian unpacking.
// If trimToLen is true, uses the last element as the original byte length.
// Mirrors JS function l(a, b).
//
// With trimToLen=false the full d*4 bytes are returned, including the
// trailing length word appended by strToUint32s — the portal's l(v, false)
// emits every word. Truncating to (d-1)*4 here shortens the ciphertext and
// makes the server fail to decrypt `info`.
func uint32sToBytes(v []uint32, trimToLen bool) []byte {
	d := len(v)
	buf := make([]byte, d*4)
	for i, w := range v {
		binary.LittleEndian.PutUint32(buf[i*4:], w)
	}
	if !trimToLen {
		return buf
	}
	c := (d - 1) * 4
	m := v[d-1]
	if m > uint32(c) {
		return nil
	}
	return buf[:m]
}

// srunBase64Encode encodes bytes using the custom base64 alphabet.
func srunBase64Encode(data []byte) string {
	// Standard base64-encode first, then remap characters.
	std := base64.StdEncoding.EncodeToString(data)
	const stdAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// Build a mapping from standard to custom alphabet.
	// Both alphabets are length 64.
	remap := [128]byte{}
	for i := 0; i < 64; i++ {
		remap[stdAlpha[i]] = srunBase64Alpha[i]
	}
	remap['='] = '='
	result := make([]byte, len(std))
	for i := range std {
		result[i] = remap[std[i]]
	}
	return string(result)
}

// srunMD5Password computes the keyed password hash used by the srun portal.
// The portal's md5(str, key) is HMAC-MD5 with key=token, message=password
// Returns the 32-char hex digest.
func srunMD5Password(token, password string) string {
	mac := hmac.New(md5.New, []byte(token))
	mac.Write([]byte(password))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// srunLogoutSign computes sign = sha1(time + username + ip + unbind + time).
// All arguments are concatenated as strings. unbind is always "1" for single logout.
func srunLogoutSign(timeStr, username, ip string) string {
	s := timeStr + username + ip + "1" + timeStr
	h := sha1.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}

// srunLoginChksum computes sha1(token+username + token+hmd5 + token+acid + token+ip + token+n + token+type + token+info).
func srunLoginChksum(token, username, hmd5, acid, ip, n, typ, info string) string {
	s := token + username +
		token + hmd5 +
		token + acid +
		token + ip +
		token + n +
		token + typ +
		token + info
	h := sha1.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}
