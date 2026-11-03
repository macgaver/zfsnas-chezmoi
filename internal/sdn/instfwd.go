package sdn

// Instance port forwards (owner decision): with the Firewall enabled, the
// VM/CT editor's port forwards are PortForwards tagged Instance/NIC and
// published on the interfaces the user picks there.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// InstanceForwardID is the stable id of an instance forward.
func InstanceForwardID(instance, nic, proto string, port int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", instance, nic, proto, port)))
	return "if" + hex.EncodeToString(h[:7])
}

// ReplaceInstanceForwards swaps the forwards of one instance NIC.
func ReplaceInstanceForwards(c *Config, instance, nic string, fwds []PortForward) {
	keep := c.PortForwards[:0:0]
	for _, f := range c.PortForwards {
		if f.Instance != instance || f.NIC != nic {
			keep = append(keep, f)
		}
	}
	c.PortForwards = append(keep, fwds...)
}

// RemoveInstanceForwards drops every forward of an instance (deleted);
// returns how many.
func RemoveInstanceForwards(c *Config, instance string) int {
	keep := c.PortForwards[:0:0]
	for _, f := range c.PortForwards {
		if f.Instance != instance {
			keep = append(keep, f)
		}
	}
	n := len(c.PortForwards) - len(keep)
	c.PortForwards = keep
	return n
}
