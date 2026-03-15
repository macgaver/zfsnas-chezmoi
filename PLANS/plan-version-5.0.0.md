# Version 5.0.0 Plan — Encryption & 2FA

## Overview

Four features:
1. **Pool Encryption** — ZFS native AES-256-GCM encryption at pool creation, key-file based, auto-loads at startup
2. **2FA / TOTP** — RFC 6238 time-based OTP for portal users, two-step login flow, setup with QR code
3. **Lock Icons** — padlock badge next to encrypted pool/dataset names throughout the UI
4. **Key Management** — full key lifecycle UI in Settings tab (generate, import, export, delete, see usage)

No new Go module dependencies — all implemented using stdlib only.

---

## Feature 1: Pool Encryption

### How ZFS Encryption Works

ZFS native encryption operates at the dataset level. When a pool is created with:
```
zpool create -O encryption=aes-256-gcm -O keyformat=raw -O keylocation=file:///path/to/key.key <pool> <devs>
```
The root dataset (and all children by default) are encrypted. The key must be loaded before the pool can be accessed after import/reboot:
```
zfs load-key -L file:///path/to/key.key <pool>
```

### Key Storage

Keys are stored in `config/keys/` directory. Each key is 32 random bytes in a file named `<uuid>.key` (mode 0600). Metadata is in `config/encryption_keys.json`.

**New file: `internal/config/config.go` additions:**
```go
// EncryptionKey is metadata for a stored ZFS encryption key.
type EncryptionKey struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
}

func LoadEncryptionKeys() ([]EncryptionKey, error)
func SaveEncryptionKeys(keys []EncryptionKey) error
func EncryptionKeyPath(id string) string  // returns config/keys/<id>.key
```

### New package: `internal/keystore/keystore.go`

Handles all key file operations:
```go
func GenerateKey(name string) (EncryptionKey, error)  // 32 rand bytes → file
func ImportKey(name string, raw []byte) (EncryptionKey, error)
func ExportKey(id string) ([]byte, error)             // returns raw 32 bytes
func DeleteKey(id string) error                        // removes file
func KeyFilePath(id string) string
func EnsureKeysDir() error
```

Keys directory: `<configDir>/keys/` — created on startup with mode 0700.

### ZFS System Functions (`system/zfs.go` additions)

```go
// CreatePool gains new optional fields.
type CreatePoolRequest struct {
    Name        string
    Layout      string
    AShift      int
    Compression string
    Dedup       string
    Devices     []string
    // Encryption:
    Encrypted   bool
    KeyFileID   string  // references an EncryptionKey.ID
}

// LoadPoolKey loads the key for an encrypted pool so it can be accessed.
func LoadPoolKey(poolName, keyFilePath string) error
    // runs: sudo zfs load-key -L file://<path> <pool>

// UnloadPoolKey unloads the key (locks the pool).
func UnloadPoolKey(poolName string) error
    // runs: sudo zfs unload-key <pool>

// GetEncryptionStatus returns "on"/"off"/"unavailable" for a pool or dataset.
func GetEncryptionStatus(name string) string
    // runs: zfs get -H -o value encryption <name>

// GetKeyStatus returns "available"/"unavailable" for an encrypted dataset.
func GetKeyStatus(name string) string
    // runs: zfs get -H -o value keystatus <name>

// GetKeyLocation returns the keylocation property value.
func GetKeyLocation(name string) string
```

`CreatePool()` internals when `Encrypted=true`:
```
sudo zpool create \
  -o ashift=<N> \
  -O encryption=aes-256-gcm \
  -O keyformat=raw \
  -O keylocation=file://<configDir>/keys/<KeyFileID>.key \
  -O atime=off \
  [-O compression=X] [-O dedup=X] \
  <name> [layout] <partuuids...>
```

### Auto-Load Keys at Startup (`main.go`)

After server starts, scan all pools for encryption. If a pool has `encryption=on` and `keystatus=unavailable` and we have the key file on disk, load it automatically:
```go
func autoLoadEncryptionKeys() {
    pools := system.GetAllPools()
    keys, _ := config.LoadEncryptionKeys()
    keyMap := map[string]string{} // id → path
    for _, k := range keys { keyMap[k.ID] = keystore.KeyFilePath(k.ID) }

    for _, pool := range pools {
        loc := system.GetKeyLocation(pool.Name)
        if !strings.HasPrefix(loc, "file://") { continue }
        if system.GetKeyStatus(pool.Name) == "available" { continue }
        // extract UUID from path, load if key file exists
        id := extractUUIDFromPath(loc)
        if path, ok := keyMap[id]; ok {
            system.LoadPoolKey(pool.Name, path)
        }
    }
}
```

### Pool Struct Addition

```go
// Pool struct (system/zfs.go) gains:
Encrypted bool   // encryption != "off"
KeyLocked bool   // keystatus == "unavailable" (key not loaded)
```

### New API Routes

```
POST   /api/encryption/keys          → HandleGenerateKey (admin)
POST   /api/encryption/keys/import   → HandleImportKey (admin)
GET    /api/encryption/keys          → HandleListKeys (admin)
DELETE /api/encryption/keys/{id}     → HandleDeleteKey (admin)
GET    /api/encryption/keys/{id}/export → HandleExportKey (admin)
POST   /api/pool/load-key            → HandleLoadKey (admin)   {pool: "name"}
POST   /api/pool/unload-key          → HandleUnloadKey (admin) {pool: "name"}
```

**New handler file:** `handlers/encryption.go`

### Frontend: Pool Creation Modal

Add "Advanced Security (optional)" collapsible section at the bottom of the pool creation modal (below dedup buttons):

```
▶ Advanced Security (optional)    [click to expand]
  ────────────────────────────────────────────────
  [ ] Enable Pool Encryption
      When enabled:
      Key: [── Select a key ──  ▼] [Manage Keys]
```

- Clicking "Enable Pool Encryption" checkbox shows the key selector row
- "Manage Keys" opens the Key Management popup modal
- The `<select>` dropdown is populated from `GET /api/encryption/keys`
- After closing Key Management popup, the dropdown is refreshed

**Key Management Popup modal** (reused in both pool creation and Settings tab):

```
┌─ Encryption Key Management ──────────────────────────────────────┐
│                                                    [Generate New] │
│                                                    [Import Key  ] │
│  Name              Created          Actions                       │
│  ─────────────────────────────────────────────────────────────   │
│  my-pool-key       2026-03-14       [Export] [Delete]             │
│  backup-key        2026-03-14       [Export] [Delete]             │
└────────────────────────────────────────────────────────────────[Close]┘
```

- "Generate New" → inline name input → `POST /api/encryption/keys` → key added to list
- "Import Key" → file picker (`.key` file, raw 32 bytes) or base64 paste dialog → name prompt → `POST /api/encryption/keys/import`
- "Export" → `GET /api/encryption/keys/{id}/export` → trigger browser download of `<name>.key` (raw bytes as blob)
- "Delete" → `DELETE /api/encryption/keys/{id}` (backend enforces not-in-use check)

Payload change to `POST /api/pool`:
```json
{
  "name": "...", "layout": "...", "ashift": 12,
  "compression": "lz4", "dedup": "off", "devices": ["..."],
  "encrypted": true,
  "key_file_id": "<uuid>"
}
```

### Dataset Encryption (display only in v5)

Child datasets inherit encryption from the pool root. The dataset modal does not expose a separate key selector in v5 — pool-level encryption covers all child datasets. The lock icon (Feature 3) will reflect inheritance.

---

## Feature 2: Two-Factor Authentication (TOTP)

### TOTP Library (stdlib only) — `internal/totp/totp.go`

Implements RFC 6238 (TOTP) and RFC 4226 (HOTP) from scratch:

```go
package totp

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha1"
    "encoding/base32"
    "encoding/binary"
    "fmt"
    "math"
    "strings"
    "time"
)

// GenerateSecret creates a new random base32-encoded TOTP secret (20 bytes).
func GenerateSecret() (string, error) {
    b := make([]byte, 20)
    if _, err := rand.Read(b); err != nil { return "", err }
    return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// OTPAuthURI returns the otpauth URI for QR code display.
func OTPAuthURI(secret, username, issuer string) string {
    return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
        issuer, username, secret, issuer)
}

// Verify checks a 6-digit code against the secret, accepting ±1 time step (90s window).
func Verify(secret, code string) bool {
    now := time.Now().Unix()
    for _, offset := range []int64{-1, 0, 1} {
        if computeTOTP(secret, now/30+offset) == code { return true }
    }
    return false
}

// computeTOTP generates the 6-digit TOTP for a given counter.
func computeTOTP(secret string, counter int64) string {
    key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
        strings.ToUpper(secret))
    if err != nil { return "" }
    msg := make([]byte, 8)
    binary.BigEndian.PutUint64(msg, uint64(counter))
    h := hmac.New(sha1.New, key)
    h.Write(msg)
    sum := h.Sum(nil)
    offset := sum[len(sum)-1] & 0x0f
    code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
    return fmt.Sprintf("%06d", code%uint32(math.Pow10(6)))
}
```

### Config Changes (`internal/config/config.go`)

```go
type User struct {
    // ... existing fields ...
    TOTPSecret  string `json:"totp_secret,omitempty"`   // base32 TOTP secret
    TOTPEnabled bool   `json:"totp_enabled,omitempty"`
}
```

### Pending Login Store (`internal/session/store.go` or new file)

```go
// PendingTOTP holds a half-authenticated session waiting for TOTP verification.
type PendingTOTP struct {
    UserID    string
    Username  string
    Role      string
    ExpiresAt time.Time
}

var pendingTOTP sync.Map // token → PendingTOTP

func CreatePendingTOTP(userID, username, role string) string // returns 32-byte hex token, 5-min TTL
func ConsumePendingTOTP(token string) (PendingTOTP, bool)   // deletes on use
```

### Login Flow Changes (`handlers/auth.go`)

**`POST /api/auth/login`** — current body: `{username, password}`

After successful bcrypt check:
- If `user.TOTPEnabled` → create pending token, return:
  ```json
  HTTP 200
  {"totp_required": true, "pending_token": "<hex>"}
  ```
  (no session cookie set)
- If `!user.TOTPEnabled` → existing flow (create session, set cookie, return `{username, role}`)

**New route: `POST /api/auth/totp`** — no auth required

Body: `{"pending_token": "<hex>", "code": "123456"}`

Flow:
1. Look up pending token → get user info, check not expired
2. `totp.Verify(user.TOTPSecret, code)` → if invalid, return 401
3. Consume (delete) pending token
4. Create full session, set cookie
5. Return `{"username": ..., "role": ...}`

### TOTP Setup Routes (`handlers/auth.go` or `handlers/users.go`)

```
POST   /api/auth/totp/setup    → HandleTOTPSetup (auth, own user only)
POST   /api/auth/totp/confirm  → HandleTOTPConfirm (auth, own user only)
DELETE /api/users/{id}/totp    → HandleDisableTOTP (admin, or own user)
```

**`POST /api/auth/totp/setup`**:
- Generates new secret, does NOT save yet
- Returns `{secret: "BASE32...", uri: "otpauth://totp/..."}`
- Frontend renders QR code from URI

**`POST /api/auth/totp/confirm`**:
- Body: `{secret: "BASE32...", code: "123456"}`
- Verifies code against secret
- If valid: saves `TOTPSecret` and `TOTPEnabled=true` to user record
- Returns 200 or 400

**`DELETE /api/users/{id}/totp`** (admin can disable for anyone; any user can disable their own):
- Sets `TOTPEnabled=false`, clears `TOTPSecret`

### QR Code Rendering (Frontend)

Since no CDN is allowed, we embed a minified QR code generator library inline in `static/index.html`. Use **qrcode-generator** by kazuhikoarase (~14 KB minified), which is MIT licensed and has zero dependencies. Add it as an inline `<script>` block at the bottom of index.html alongside other embedded scripts.

Usage:
```js
function renderQRCode(containerId, text) {
    var qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    document.getElementById(containerId).innerHTML = qr.createImgTag(4);
}
```

### User Edit Modal — 2FA Section

The user edit modal (Edit button on own user row) gains a "Two-Factor Authentication" section below the password field. This section is only shown when editing your **own** account (not admin editing others — admin uses the separate disable route).

```
Two-Factor Authentication
─────────────────────────
○ Disabled    ● Enabled                ← toggle

[When enabling — setup flow:]

  Scan this QR code with your authenticator app:
  ┌──────────┐
  │ QR CODE  │
  └──────────┘
  Or enter manually: JBSWY3DPEHPK3PXP

  Verify setup — enter the code from your app:
  [______]  ← 6-digit input

  ⚠ You must verify a code before saving.

[When disabling:]
  This will remove 2FA from your account.
```

Save button is disabled (greyed) until TOTP is verified when enabling.

Audit log entries: `"2fa_enabled"`, `"2fa_disabled"` — add `Action2FAEnabled`, `Action2FADisabled` constants.

---

## Feature 3: Lock Icons

### Data Propagation

**Pool list** (`GET /api/pools`): `Pool.Encrypted` and `Pool.KeyLocked` added (see Feature 1). These come from a single `zfs get -H -o name,value encryption,keystatus <pool>` call.

**Dataset list** (`GET /api/datasets`): `Dataset` struct gains:
```go
Encrypted  bool   // encryption property != "off"
KeyLocked  bool   // keystatus == "unavailable"
```
Populated by `zfs get -H -o name,value encryption,keystatus` batch call on the dataset list.

### Frontend Display

Wherever a pool name or dataset name is rendered, prepend a lock icon badge if `encrypted=true`:

```js
// Pool name in sidebar and Pool tab header:
poolName + (pool.encrypted ? ' <span class="lock-badge" title="Encrypted' + (pool.key_locked ? ' — key not loaded' : '') + '">🔒</span>' : '')

// Dataset name in dataset table Name column:
ds.name + (ds.encrypted ? ' <span class="lock-badge" title="Encrypted">🔒</span>' : '')
```

CSS for `.lock-badge`:
```css
.lock-badge {
    font-size: 0.85em;
    opacity: 0.8;
    vertical-align: middle;
    cursor: default;
}
```

When `key_locked=true` (key not loaded), the badge shows 🔓 (open lock, orange color) with tooltip "Encrypted — key not loaded" and a small "Load Key" action link in the pool row.

---

## Feature 4: Key Management in Settings Tab

### New Section in Settings Tab

Below existing settings sections, add "Encryption Key Management":

```
Encryption Key Management
─────────────────────────
                                          [Generate New Key] [Import Key]
 Name              Created            Used By              Actions
 ─────────────────────────────────────────────────────────────────────
 my-pool-key       2026-03-14         tank, backup         [Export] [Delete]
 spare-key         2026-03-14         (unused)             [Export] [Delete]
```

**"Used By" column:** calls a new helper on the backend:

```
GET /api/encryption/keys/usage
```

Returns:
```json
{
  "my-pool-key-uuid": ["tank", "backup"],
  "spare-key-uuid": []
}
```

Computed by calling `zfs get -H -o name,value keylocation` across all pools/datasets and matching `file://` paths against key UUIDs.

**Delete**: disabled (grey, "In Use" tooltip) when `Used By` is non-empty. Backend also enforces this check and returns 409 if the key is in use.

**Generate New Key flow:**
1. Click "Generate New Key"
2. Inline form appears: text input for name + [Create] [Cancel]
3. `POST /api/encryption/keys {"name": "..."}` → key generated, table refreshes

**Import Key flow:**
1. Click "Import Key"
2. Small modal: name input + file picker (accept `.key`, raw binary) + [Import] [Cancel]
3. File read client-side as ArrayBuffer, sent as base64 in `POST /api/encryption/keys/import {"name": "...", "key_b64": "..."}`
4. Backend validates length (must be exactly 32 bytes) and saves

**Export Key:**
- `GET /api/encryption/keys/{id}/export`
- Backend returns raw bytes with `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="<name>.key"`
- Important: display a warning modal before downloading ("Keep this key safe. If lost, encrypted data cannot be recovered.")

This Settings section is **identical in functionality** to the Key Management popup from Feature 1. The popup used in pool creation calls the same API routes and is essentially the same UI rendered in a modal rather than the Settings tab.

---

## New Files Summary

| File | Purpose |
|------|---------|
| `internal/totp/totp.go` | TOTP generation & verification (stdlib only) |
| `internal/keystore/keystore.go` | Key file CRUD operations |
| `handlers/encryption.go` | Encryption key API handlers |

## Modified Files Summary

| File | Changes |
|------|---------|
| `internal/config/config.go` | `User.TOTPSecret`, `User.TOTPEnabled`, `EncryptionKey` type + CRUD |
| `internal/session/store.go` | Pending TOTP store |
| `system/zfs.go` | `CreatePool` encryption flags, `LoadPoolKey`, `UnloadPoolKey`, `GetEncryptionStatus`, `GetKeyStatus`, `Pool.Encrypted`, `Pool.KeyLocked`, `Dataset.Encrypted`, `Dataset.KeyLocked` |
| `handlers/auth.go` | Two-step login, `POST /api/auth/totp`, TOTP setup/confirm routes |
| `handlers/users.go` | `DELETE /api/users/{id}/totp` |
| `handlers/router.go` | Register all new routes |
| `main.go` | `autoLoadEncryptionKeys()` goroutine at startup, `keystore.EnsureKeysDir()` |
| `static/index.html` | Pool creation Advanced Security section, user edit 2FA section, lock icons, Key Management settings section, QR code library (inline), login 2FA step |
| `static/style.css` | Lock badge styles, Advanced Security section styles |
| `internal/audit/audit.go` | `Action2FAEnabled`, `Action2FADisabled` |

## New API Routes Summary

```
# Encryption keys
GET    /api/encryption/keys            → list all keys (metadata only)
POST   /api/encryption/keys            → generate new key {name}
POST   /api/encryption/keys/import     → import key {name, key_b64}
GET    /api/encryption/keys/usage      → map of key_id → []pool/dataset names
GET    /api/encryption/keys/{id}/export → download raw key file
DELETE /api/encryption/keys/{id}       → delete key (fails if in use)

# Pool key operations
POST   /api/pool/load-key              → {pool} load key for encrypted pool
POST   /api/pool/unload-key            → {pool} unload key (lock pool)

# TOTP
POST   /api/auth/totp                  → {pending_token, code} → full login
POST   /api/auth/totp/setup            → generate secret+URI (not saved yet)
POST   /api/auth/totp/confirm          → {secret, code} → save if verified
DELETE /api/users/{id}/totp            → disable 2FA for user
```

## Feature 5: SSD Disk Icon

Replace the current CD-ROM/disk icon used for drives in the Disks tab with a proper SSD/drive icon. The existing icon (likely a Unicode character or SVG) should be swapped for an SSD-style block device icon. This affects the disk table in the Disks tab and anywhere else a disk icon appears in the UI.

Implementation: find the icon definition in `static/index.html` or `static/style.css` and replace with an appropriate SVG or Unicode symbol (e.g., a drive/SSD shape).

---

## Implementation Order

1. `internal/totp/totp.go` + tests
2. `internal/keystore/keystore.go`
3. `internal/config/config.go` — add types + CRUD
4. `system/zfs.go` — encryption functions + Pool/Dataset struct additions
5. `main.go` — startup key auto-load, keysDir init
6. `handlers/encryption.go` — key management handlers
7. `handlers/auth.go` — two-step login + TOTP setup/confirm
8. `handlers/router.go` — register routes
9. `static/index.html` — all UI: login flow, user edit 2FA, pool creation encryption, lock icons, settings key management + inline QR lib
10. `static/style.css` — styles
11. Build, test, deploy

## Security Notes

- Key files: mode 0600, owned by the zfsnas service user
- `config/keys/` directory: mode 0700
- TOTP secrets: stored in `users.json` (mode 0640) — acceptable since file is already protected
- Pending TOTP tokens: 5-minute TTL, single-use (consumed on first valid TOTP verify)
- Export key warning dialog prevents accidental exposure
- Delete key blocked while in use (both frontend UI and backend enforcement)
- Admin cannot view TOTP secrets (setup/confirm flow keeps secret client-side until confirm succeeds)
