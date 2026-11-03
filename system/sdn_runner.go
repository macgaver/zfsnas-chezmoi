package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// cmdRunner runs a privileged command. The SDN code never builds "sudo" argv
// itself: the real runner adds it when the portal is not root, and tests swap
// in a recorder.
type cmdRunner interface {
	Run(stdin []byte, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

// sdnDetachedArgv: ifup starts daemons (pppd, dhclient) that must not live
// in the portal's cgroup — a portal restart or upgrade would kill them, and
// so would the end of the revert service. They get a scope of their own.
func sdnDetachedArgv(name string, args []string) (string, []string) {
	if name != "ifup" {
		return name, args
	}
	return "systemd-run", append([]string{"--scope", "--quiet", "--collect", "--", name}, args...)
}

func (execRunner) Run(stdin []byte, name string, args ...string) ([]byte, error) {
	label := name
	name, args = sdnDetachedArgv(name, args)
	var cmd *exec.Cmd
	if os.Getuid() == 0 {
		cmd = exec.Command(name, args...)
	} else {
		cmd = exec.Command("sudo", append([]string{"-n", name}, args...)...)
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return out, fmt.Errorf("%s %s: %s", label, strings.Join(args, " "), msg)
	}
	return out, nil
}

var sdnRun cmdRunner = execRunner{}

// sdnWriteInterfaces writes /etc/network/interfaces (ensures bridge-utils /
// vlan helper packages like every other interfaces writer).
var sdnWriteInterfaces = func(path string, data []byte) error {
	if err := writeInterfacesFile(path, data); err != nil {
		return err
	}
	// VLAN stanzas must not lag behind the saved config after a power cut.
	if f, err := os.Open(path); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return nil
}

// sdnWriteFile writes a root-owned system file: direct when root, sudo tee
// otherwise.
var sdnWriteFile = func(path string, data []byte) error {
	if os.Getuid() == 0 {
		return os.WriteFile(path, data, 0644)
	}
	_, err := sdnRun.Run(data, "tee", path)
	return err
}

// sdnWriteSecret writes a root-only (0600) file, such as pppd secrets.
var sdnWriteSecret = func(path string, data []byte) error {
	if os.Getuid() == 0 {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		return os.Chmod(path, 0600)
	}
	// Mode first, content after: the secret is never world-readable.
	if _, err := sdnRun.Run(nil, "install", "-m", "600", "/dev/null", path); err != nil {
		return err
	}
	_, err := sdnRun.Run(data, "tee", path)
	return err
}

// sdnRemoveFile deletes a root-owned file (missing is fine).
var sdnRemoveFile = func(path string) error {
	if os.Getuid() == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	_, err := sdnRun.Run(nil, "rm", "-f", path)
	return err
}

// SDNRunner is the command runner interface, exported for handler tests.
type SDNRunner = cmdRunner

// SDNSetTestEnv redirects every SDN side effect into dir and routes commands
// to run (a recorder). Test-only; returns the restore function.
func SDNSetTestEnv(run SDNRunner, dir string) func() {
	oldRun, oldIf, oldSysctl, oldUnit, oldRunDir, oldSys, oldWriteIf, oldWrite :=
		sdnRun, hostInterfacesPath, sdnSysctlPath, sdnUnitPath, sdnRunDir, sdnSysClassNet, sdnWriteInterfaces, sdnWriteFile
	sdnRun = run
	oldKey := sdnIncusNetKey
	sdnIncusNetKey = func(string, string) string { return "" }
	oldWait := sdnBootWait
	sdnBootWait = 0
	hostInterfacesPath = dir + "/interfaces"
	sdnSysctlPath = dir + "/90-znas-sdn.conf"
	sdnUnitPath = dir + "/znas-sdn.service"
	sdnRunDir = dir + "/run"
	sdnSysClassNet = dir + "/sys"
	sdnWriteInterfaces = func(p string, b []byte) error { return os.WriteFile(p, b, 0644) }
	sdnWriteFile = func(p string, b []byte) error { return os.WriteFile(p, b, 0644) }
	oldSecret, oldRemove, oldPPP := sdnWriteSecret, sdnRemoveFile, sdnPPPDir
	sdnWriteSecret = func(p string, b []byte) error { return os.WriteFile(p, b, 0600) }
	sdnRemoveFile = func(p string) error { return os.RemoveAll(p) }
	sdnPPPDir = dir + "/ppp"
	oldConf, oldWG, oldLease := sdnDnsmasqConf, sdnWGDir, sdnLegacyLeasePath
	sdnDnsmasqConf, sdnWGDir, sdnLegacyLeasePath = dir+"/znas-sdn/dnsmasq.conf", dir+"/wireguard", dir+"/leases"
	oldDHCPDir, oldLeaseDir, oldHosts, oldStatus, oldWaitDHCP := sdnDHCPDir, sdnLeaseDir, sdnHostsDir, sdnDHCPStatusPath, sdnDHCPWait
	sdnDHCPDir, sdnLeaseDir, sdnHostsDir, sdnDHCPStatusPath, sdnDHCPWait = dir+"/znas-sdn/dhcp.d", dir+"/leasedir", dir+"/hosts.d", dir+"/dhcp-status.json", 0
	oldQLog, oldBL := sdnQueryLog, sdnBlocklistFile
	sdnQueryLog, sdnBlocklistFile = dir+"/queries.log", dir+"/blocklist.hosts"
	oldAddrs := sdnHostAddrs
	sdnHostAddrs = func() map[string][]string { return nil }
	oldIDS, oldThr, oldSock, oldState := sdnIDSConf, sdnIDSThreshold, sdnIDSSocket, sdnIDSState
	sdnIDSConf, sdnIDSThreshold, sdnIDSSocket, sdnIDSState = dir+"/znas-sdn/suricata.yaml", dir+"/znas-sdn/threshold.config", dir+"/ids.sock", dir+"/ids-state.json"
	oldDD, oldDDCache := sdnDDClientConf, sdnDDClientCache
	sdnDDClientConf, sdnDDClientCache = dir+"/znas-sdn/ddclient.conf", dir+"/ddclient.cache"
	return func() {
		sdnDDClientConf, sdnDDClientCache = oldDD, oldDDCache
		sdnIDSConf, sdnIDSThreshold, sdnIDSSocket, sdnIDSState = oldIDS, oldThr, oldSock, oldState
		sdnHostAddrs = oldAddrs
		sdnDnsmasqConf, sdnWGDir, sdnLegacyLeasePath = oldConf, oldWG, oldLease
		sdnDHCPDir, sdnLeaseDir, sdnHostsDir, sdnDHCPStatusPath, sdnDHCPWait = oldDHCPDir, oldLeaseDir, oldHosts, oldStatus, oldWaitDHCP
		sdnQueryLog, sdnBlocklistFile = oldQLog, oldBL
		sdnWriteSecret, sdnRemoveFile, sdnPPPDir = oldSecret, oldRemove, oldPPP
		sdnIncusNetKey = oldKey
		sdnBootWait = oldWait
		sdnRun, hostInterfacesPath, sdnSysctlPath, sdnUnitPath, sdnRunDir, sdnSysClassNet, sdnWriteInterfaces, sdnWriteFile =
			oldRun, oldIf, oldSysctl, oldUnit, oldRunDir, oldSys, oldWriteIf, oldWrite
	}
}
