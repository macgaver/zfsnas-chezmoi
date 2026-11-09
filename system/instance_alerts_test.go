package system

import "testing"

func TestInstanceNameFromDataset(t *testing.T) {
	for ds, want := range map[string]string{
		"NVMEPool/LXD-znas3/virtual-machines/znas-appliance.block": "znas-appliance",
		"tank/incus/containers/applab-client":                      "applab-client",
		"tank/incus/containers/web1/some/child":                    "web1",
		"tank/incus/virtual-machines/proj_vm1":                     "vm1",
		"tank/data/photos":                                         "",
		"tank/virtual-machines-archive/x":                          "",
	} {
		if got := InstanceNameFromDataset(ds); got != want {
			t.Errorf("%s: %q, want %q", ds, got, want)
		}
	}
}

func TestInstanceAlertsMuted(t *testing.T) {
	old := instanceConfigGet
	t.Cleanup(func() { instanceConfigGet = old })
	instanceConfigGet = func(name, key string) string {
		if name == "test-vm" && key == instanceNoAlertsKey {
			return "true"
		}
		return ""
	}
	if !InstanceAlertsMuted("test-vm") || InstanceAlertsMuted("prod-vm") || InstanceAlertsMuted("") || InstanceAlertsMuted("bad;name") {
		t.Fatal("mute lookup wrong")
	}
	if !DatasetAlertsMuted("tank/incus/virtual-machines/test-vm.block") || DatasetAlertsMuted("tank/data") {
		t.Fatal("dataset mute lookup wrong")
	}
}
