package sdn

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"zfsnas/internal/backup"
)

// ExportFile is the plaintext inside a .znasfw file — all of the feature's
// configuration (not traffic data, not history), sealed with the same
// password scheme as the .znasbak backup.
type ExportFile struct {
	Kind        string    `json:"kind"`   // "znas-sdn"
	Schema      int       `json:"schema"` // 1
	ZNASVersion string    `json:"znas_version"`
	Hostname    string    `json:"hostname"`
	CreatedAt   time.Time `json:"created_at"`
	Config      *Config   `json:"config"`
}

// ErrNotSDNExport is returned for a valid sealed file that is not a
// firewall export (e.g. a .znasbak).
var ErrNotSDNExport = errors.New("this file is not a ZNAS firewall export (.znasfw)")

func Export(c *Config, meta ExportFile, password string) ([]byte, error) {
	meta.Kind, meta.Schema, meta.Config = "znas-sdn", 1, c
	b, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return backup.Seal(password, b)
}

func Import(data []byte, password string) (*ExportFile, error) {
	plain, err := backup.Open(password, data)
	if err != nil {
		return nil, err
	}
	var f ExportFile
	if json.Unmarshal(plain, &f) != nil || f.Kind != "znas-sdn" || f.Config == nil {
		return nil, ErrNotSDNExport
	}
	f.Config.Normalize()
	return &f, nil
}

// DevicesNeeded lists the kernel devices a config expects to find on the
// machine: physical ports, adopted bridges, and VLAN parents.
func DevicesNeeded(c *Config) []string {
	seen := map[string]bool{}
	for _, in := range c.Interfaces {
		switch in.Kind {
		case "vlan", "pppoe":
			seen[in.Parent] = true
		case "wireguard": // created here
		default:
			seen[in.Device] = true
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// RemapDevices returns a copy of c with kernel device names renamed per m
// (old → new): moving to new hardware renames NICs. VLAN device names are
// recomputed from their new parent.
func RemapDevices(c *Config, m map[string]string) *Config {
	b, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(b, &out)
	re := func(s string) string {
		if n, ok := m[s]; ok && n != "" {
			return n
		}
		return s
	}
	for i := range out.Interfaces {
		in := &out.Interfaces[i]
		if in.Kind == "vlan" || in.Kind == "pppoe" {
			in.Parent = re(in.Parent)
		} else {
			in.Device = re(in.Device)
		}
	}
	out.Settings.MgmtInterface = re(out.Settings.MgmtInterface)
	out.Normalize()
	return &out
}
