package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238): 6 цифр, шаг 30 с, SHA-1 — совместимо с Google Authenticator и аналогами.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return b32.EncodeToString(b)
}

func totpCode(secret string, step int64) string {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	o := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// totpCheck возвращает шаг, на котором код совпал (окно ±1 шаг), или 0.
func totpCheck(secret, code string, last int64) int64 {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0
	}
	now := time.Now().Unix() / 30
	for _, st := range []int64{now, now - 1, now + 1} {
		if st > last && hmac.Equal([]byte(totpCode(secret, st)), []byte(code)) {
			return st
		}
	}
	return 0
}

func totpURI(user, secret string) string {
	label := url.PathEscape("Droply:" + user)
	return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=Droply" // digits=6, period=30 — значения по умолчанию; короче URI → влезает в QR уровня H
}
