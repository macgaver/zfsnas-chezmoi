// Package backup implements the ZNAS configuration backup file (.znasbak):
// a password-encrypted tar.gz of the portal configuration plus the system
// state needed to rebuild a server (portal-managed Linux accounts, SMB
// password hashes, Incus networks/profiles/datastores).
//
// File layout (all integers big-endian):
//
//	magic      "ZNASBAK1"      8 bytes
//	kdf iters  uint32          PBKDF2-HMAC-SHA256 iterations
//	salt       16 bytes
//	nonce      12 bytes        AES-GCM nonce
//	ciphertext …               AES-256-GCM(tar.gz), tag appended
//
// The header (magic → nonce) is passed as GCM additional data, so changing
// the iteration count or salt is detected like any other tampering. A wrong
// password and a damaged file are indistinguishable on purpose: both fail
// authentication and nothing is extracted.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	magic        = "ZNASBAK1"
	saltLen      = 16
	nonceLen     = 12
	headerLen    = len(magic) + 4 + saltLen + nonceLen
	defaultIters = 600_000 // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
	// MaxFileSize bounds what Open accepts (and what an upload may be).
	MaxFileSize = 512 << 20
	// MinPasswordLen is enforced at export.
	MinPasswordLen = 12
)

// ErrBadPassword is returned for a wrong password or a damaged/tampered file.
var ErrBadPassword = errors.New("wrong password or damaged backup file")

// ErrNotBackup is returned when the data does not start with the magic.
var ErrNotBackup = errors.New("not a ZNAS backup file (.znasbak)")

// iters is a var so tests can use a cheap KDF.
var iters uint32 = defaultIters

// Seal encrypts plaintext with a key derived from password.
func Seal(password string, plaintext []byte) ([]byte, error) {
	if len(password) < MinPasswordLen {
		return nil, fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := make([]byte, 0, headerLen)
	header = append(header, magic...)
	header = binary.BigEndian.AppendUint32(header, iters)
	header = append(header, salt...)
	header = append(header, nonce...)

	gcm, err := newGCM(password, salt, iters)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(header, nonce, plaintext, header), nil
}

// Open decrypts data produced by Seal.
func Open(password string, data []byte) ([]byte, error) {
	if len(data) < headerLen || !bytes.Equal(data[:len(magic)], []byte(magic)) {
		return nil, ErrNotBackup
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("backup file is larger than %d MB", MaxFileSize>>20)
	}
	header := data[:headerLen]
	n := binary.BigEndian.Uint32(header[len(magic):])
	if n < 10_000 || n > 50_000_000 {
		return nil, ErrBadPassword // absurd parameters: treat as damaged
	}
	salt := header[len(magic)+4 : len(magic)+4+saltLen]
	nonce := header[len(magic)+4+saltLen:]
	gcm, err := newGCM(password, salt, n)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, data[headerLen:], header)
	if err != nil {
		return nil, ErrBadPassword
	}
	return plain, nil
}

func newGCM(password string, salt []byte, n uint32) (cipher.AEAD, error) {
	key := pbkdf2SHA256([]byte(password), salt, int(n), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// pbkdf2SHA256 is RFC 8018 PBKDF2 with HMAC-SHA256 (stdlib only — the
// project takes no new module dependencies).
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	u := make([]byte, hLen)
	for b := 1; b <= blocks; b++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(b))
		prf.Write(buf)
		u = prf.Sum(u[:0])
		t := make([]byte, hLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
