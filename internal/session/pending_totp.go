package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const pendingTOTPDuration = 5 * time.Minute

// PendingTOTP holds a half-authenticated session waiting for TOTP verification.
type PendingTOTP struct {
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

var (
	pendingMu   sync.Mutex
	pendingTOTP = map[string]*PendingTOTP{}
)

// CreatePendingTOTP generates a short-lived (5-min) pending token for two-step login.
func CreatePendingTOTP(userID, username, role string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	pendingMu.Lock()
	pendingTOTP[token] = &PendingTOTP{
		UserID:    userID,
		Username:  username,
		Role:      role,
		ExpiresAt: time.Now().Add(pendingTOTPDuration),
	}
	pendingMu.Unlock()
	return token, nil
}

// ConsumePendingTOTP looks up and deletes the pending token (single-use).
// Returns the PendingTOTP and true if found and not expired.
func ConsumePendingTOTP(token string) (*PendingTOTP, bool) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	p, ok := pendingTOTP[token]
	if !ok {
		return nil, false
	}
	delete(pendingTOTP, token)
	if time.Now().After(p.ExpiresAt) {
		return nil, false
	}
	return p, true
}
