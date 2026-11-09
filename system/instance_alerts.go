package system

import (
	"regexp"
	"strings"
)

// instanceNoAlertsKey is set ("true") on an instance whose notifications
// the admin muted from its edit dialog ("No alerts for this instance").
const instanceNoAlertsKey = "user.zfsnas.no_alerts"

// instanceConfigGet is a var so tests can fake Incus.
var instanceConfigGet = ComposeGetConfigKey

// InstanceAlertsMuted reports whether notifications about this VM or
// container are muted. Unknown instance or Incus error → not muted.
func InstanceAlertsMuted(name string) bool {
	if name == "" || !validInstanceName(name) {
		return false
	}
	return instanceConfigGet(name, instanceNoAlertsKey) == "true"
}

// Incus storage layout: <pool>/<prefix>/{virtual-machines,containers}/<name>[.block][/...]
var instanceDatasetRe = regexp.MustCompile(`/(?:virtual-machines|containers)/([A-Za-z0-9][A-Za-z0-9_-]*)(?:\.block)?(?:/|$)`)

// InstanceNameFromDataset returns the Incus instance a dataset belongs to
// ("" for an ordinary dataset), so schedule alerts can honour the mute.
// A project-prefixed name ("proj_vm1") yields "vm1".
func InstanceNameFromDataset(ds string) string {
	m := instanceDatasetRe.FindStringSubmatch(ds)
	if m == nil {
		return ""
	}
	name := m[1]
	if i := strings.LastIndex(name, "_"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func validInstanceName(n string) bool {
	if len(n) > 63 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// DatasetAlertsMuted: the dataset belongs to an instance whose alerts are muted.
func DatasetAlertsMuted(ds string) bool {
	return InstanceAlertsMuted(InstanceNameFromDataset(ds))
}
