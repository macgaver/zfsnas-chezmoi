package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

// GenerateSecret creates a new random base32-encoded TOTP secret (20 bytes / 160 bits).
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// OTPAuthURI returns the otpauth:// URI for QR code display with an authenticator app.
func OTPAuthURI(secret, username, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer),
		url.PathEscape(username),
		secret,
		url.QueryEscape(issuer),
	)
}

// Verify checks a 6-digit TOTP code against the secret.
// Accepts ±1 time step (90-second window) to tolerate clock skew.
func Verify(secret, code string) bool {
	if len(code) != 6 {
		return false
	}
	counter := time.Now().Unix() / 30
	for _, offset := range []int64{-1, 0, 1} {
		if computeTOTP(secret, counter+offset) == code {
			return true
		}
	}
	return false
}

// computeTOTP generates the 6-digit TOTP code for a given counter value (RFC 4226 / RFC 6238).
func computeTOTP(secret string, counter int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}

	// HOTP: HMAC-SHA1(key, counter)
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	sum := h.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%uint32(math.Pow10(6)))
}
