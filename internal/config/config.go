package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	RoleAdmin    = "admin"
	RoleReadOnly = "read-only"
	RoleSMBOnly  = "smb-only"
)

// AppConfig holds top-level application settings.
type AppConfig struct {
	Port              int       `json:"port"`
	StorageUnit       string    `json:"storage_unit,omitempty"`        // "gb" (1000-based) or "gib" (1024-based)
	SMARTLastRefresh  time.Time `json:"smart_last_refresh,omitempty"`
	WeeklyScrub       bool      `json:"weekly_scrub"`                  // auto-scrub every Sunday at 02:00 (default: true)
	LiveUpdateEnabled bool      `json:"live_update_enabled,omitempty"` // enable in-place binary self-update
	MaxSmbdProcesses  int       `json:"max_smbd_processes,omitempty"`  // Samba max smbd processes (0 = use default 100)
}

// UserPreferences holds per-user UI preferences persisted across sessions.
type UserPreferences struct {
	ActivityBarCollapsed bool `json:"activity_bar_collapsed,omitempty"`
}

// User represents a portal or SMB-only user.
type User struct {
	ID           string          `json:"id"`
	Username     string          `json:"username"`
	Email        string          `json:"email"`
	PasswordHash string          `json:"password_hash"`
	Role         string          `json:"role"` // admin, read-only, smb-only
	CreatedAt    time.Time       `json:"created_at"`
	Preferences  UserPreferences `json:"preferences,omitempty"`
}

var (
	configDir string
	mu        sync.RWMutex
)

// Init creates the config directory and stores its path.
func Init(dir string) error {
	configDir = dir
	return os.MkdirAll(dir, 0750)
}

// Dir returns the current config directory path.
func Dir() string {
	return configDir
}

func loadJSON(filename string, v interface{}) error {
	path := filepath.Join(configDir, filename)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func saveJSON(filename string, v interface{}) error {
	mu.Lock()
	defer mu.Unlock()
	path := filepath.Join(configDir, filename)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

// LoadAppConfig loads or initializes application config with defaults.
func LoadAppConfig() (*AppConfig, error) {
	// Detect whether the config file already exists before loading, so we can
	// distinguish a fresh install (apply all defaults) from an existing config
	// that has WeeklyScrub explicitly set to false.
	fresh := false
	if _, err := os.Stat(filepath.Join(configDir, "config.json")); os.IsNotExist(err) {
		fresh = true
	}

	cfg := &AppConfig{Port: 8443}
	if err := loadJSON("config.json", cfg); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = 8443
	}
	if cfg.StorageUnit == "" {
		cfg.StorageUnit = "gb"
	}
	if cfg.MaxSmbdProcesses == 0 {
		cfg.MaxSmbdProcesses = 100
	}
	// Default weekly scrub to enabled on fresh installs. Existing configs that
	// have WeeklyScrub explicitly saved (true or false) are left untouched.
	if fresh {
		cfg.WeeklyScrub = true
	}
	return cfg, nil
}

// APIKeyEntry represents a named API key used by external integrations (e.g. homepage widget).
type APIKeyEntry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

// LoadAPIKeys loads all API keys from disk.
func LoadAPIKeys() ([]APIKeyEntry, error) {
	var keys []APIKeyEntry
	if err := loadJSON("api_keys.json", &keys); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []APIKeyEntry{}
	}
	return keys, nil
}

// SaveAPIKeys persists all API keys to disk.
func SaveAPIKeys(keys []APIKeyEntry) error {
	return saveJSON("api_keys.json", keys)
}

// SaveAppConfig persists application config.
func SaveAppConfig(cfg *AppConfig) error {
	return saveJSON("config.json", cfg)
}

// LoadUsers loads all users from disk.
func LoadUsers() ([]User, error) {
	var users []User
	if err := loadJSON("users.json", &users); err != nil {
		return nil, err
	}
	if users == nil {
		users = []User{}
	}
	return users, nil
}

// SaveUsers persists all users to disk.
func SaveUsers(users []User) error {
	return saveJSON("users.json", users)
}

// FindUserByUsername returns the user with the given username, or nil.
func FindUserByUsername(users []User, username string) *User {
	for i := range users {
		if users[i].Username == username {
			return &users[i]
		}
	}
	return nil
}

// FindUserByID returns the user with the given ID, or nil.
func FindUserByID(users []User, id string) *User {
	for i := range users {
		if users[i].ID == id {
			return &users[i]
		}
	}
	return nil
}
