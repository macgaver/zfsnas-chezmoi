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
	WeeklyScrub       bool      `json:"weekly_scrub,omitempty"`        // auto-scrub every Sunday at 02:00
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
	return cfg, nil
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
