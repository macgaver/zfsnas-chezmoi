package sdn

import (
	"strings"
	"testing"
)

func TestInstanceForwardID(t *testing.T) {
	a := InstanceForwardID("web", "eth0", "tcp", 443)
	if !idRe.MatchString(a) || a != InstanceForwardID("web", "eth0", "tcp", 443) {
		t.Fatalf("id %q not valid/stable", a)
	}
	if a == InstanceForwardID("web", "eth0", "udp", 443) || a == InstanceForwardID("web2", "eth0", "tcp", 443) {
		t.Fatal("ids collide")
	}
}

func TestReplaceInstanceForwards(t *testing.T) {
	c := &Config{PortForwards: []PortForward{
		{ID: "manual1", PubPorts: "80", Target: "10.0.0.5"},
		{ID: "old1", Instance: "web", NIC: "eth0", PubPorts: "8080"},
		{ID: "other1", Instance: "web", NIC: "eth1", PubPorts: "22"},
	}}
	ReplaceInstanceForwards(c, "web", "eth0", []PortForward{{ID: "new1", Instance: "web", NIC: "eth0", PubPorts: "443"}})
	var ids []string
	for _, f := range c.PortForwards {
		ids = append(ids, f.ID)
	}
	if strings.Join(ids, ",") != "manual1,other1,new1" {
		t.Fatalf("got %v", ids)
	}
	if n := RemoveInstanceForwards(c, "web"); n != 2 || len(c.PortForwards) != 1 {
		t.Fatalf("remove: %d left %v", n, c.PortForwards)
	}
}

func TestValidate_PausedInstanceForwardNeedsNoTarget(t *testing.T) {
	c := ownerSample()
	c.PortForwards = append(c.PortForwards, PortForward{ID: InstanceForwardID("web", "eth0", "tcp", 443), Enabled: true, Protocol: "tcp",
		PubPorts: "443", TargetPorts: "443", Instance: "web", NIC: "eth0"})
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatalf("paused instance forward without target rejected: %v", err)
	}
	c.PortForwards[len(c.PortForwards)-1].Interfaces = []string{c.Interfaces[0].ID}
	if err := c.Validate(); err != nil {
		t.Fatalf("published forward waiting for its address rejected: %v", err)
	}
	script, err := Compile(c, Env{PortalPorts: []int{8443}, SSHPort: 22})
	if err != nil || strings.Contains(script, "pf:"+c.PortForwards[len(c.PortForwards)-1].ID) {
		t.Fatalf("forward without address compiled: %v", err)
	}
}

func TestValidate_PausedInstanceForwardStillChecksPorts(t *testing.T) {
	c := ownerSample()
	c.PortForwards = append(c.PortForwards, PortForward{ID: "ifabc", Enabled: true, Protocol: "tcp",
		PubPorts: "443", TargetPorts: "99999", Instance: "web", NIC: "eth0"})
	c.Normalize()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "target_ports") {
		t.Fatalf("bad port accepted: %v", err)
	}
}

func TestValidate_PortForwardCollision(t *testing.T) {
	c := ownerSample()
	wan := c.Interfaces[0].ID
	c.PortForwards = []PortForward{
		{ID: "pfa", Enabled: true, Protocol: "tcp", PubPorts: "8000-8010", TargetPorts: "80", Target: "10.0.0.5", Interfaces: []string{wan}},
		{ID: "pfb", Enabled: true, Protocol: "tcpudp", PubPorts: "8005", TargetPorts: "80", Target: "10.0.0.6", Interfaces: []string{wan}, Description: "web2"},
	}
	c.Normalize()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "already forwarded") {
		t.Fatalf("collision accepted: %v", err)
	}
	c.PortForwards[1].Protocol = "udp"
	if err := c.Validate(); err != nil {
		t.Fatalf("tcp vs udp is no collision: %v", err)
	}
	c.PortForwards[1].Protocol, c.PortForwards[1].Interfaces = "tcp", nil // paused
	c.PortForwards[1].Instance = "web"
	if err := c.Validate(); err != nil {
		t.Fatalf("paused forward collides: %v", err)
	}
}
