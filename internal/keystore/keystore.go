// Package keystore manages raw AES-256 key files for ZFS native encryption.
// Each key is 32 random bytes stored in <configDir>/keys/<uuid>.key (mode 0600).
// Key metadata (id, name, created_at) is persisted in config/encryption_keys.json.
package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

var keysDir string

// Init sets the base config directory. Must be called before any other function.
func Init(configDir string) error {
	keysDir = filepath.Join(configDir, "keys")
	return os.MkdirAll(keysDir, 0700)
}

// KeyFilePath returns the absolute path for a key file given its UUID.
func KeyFilePath(id string) string {
	return filepath.Join(keysDir, id+".key")
}

// GenerateKey creates a new 32-byte random key file and returns its path.
func GenerateKey(id string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("keystore: generate random bytes: %w", err)
	}
	return writeKeyFile(id, raw)
}

// ImportKeyHex writes a key from a hex-encoded string into the key store.
// hexStr must decode to exactly 32 bytes (64 hex characters).
func ImportKeyHex(id, hexStr string) error {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("keystore: invalid hex string: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("keystore: key must be exactly 32 bytes (got %d)", len(raw))
	}
	return writeKeyFile(id, raw)
}

// ExportKeyHex reads the key file and returns it as a lowercase hex string.
func ExportKeyHex(id string) (string, error) {
	raw, err := os.ReadFile(KeyFilePath(id))
	if err != nil {
		return "", fmt.Errorf("keystore: read key file: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("keystore: corrupt key file (expected 32 bytes, got %d)", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// DeleteKey removes a key file from disk.
func DeleteKey(id string) error {
	path := KeyFilePath(id)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("keystore: delete key file: %w", err)
	}
	return nil
}

// Exists reports whether the key file for id exists on disk.
func Exists(id string) bool {
	_, err := os.Stat(KeyFilePath(id))
	return err == nil
}

func writeKeyFile(id string, raw []byte) error {
	path := KeyFilePath(id)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return fmt.Errorf("keystore: write key file: %w", err)
	}
	return nil
}
