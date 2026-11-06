package alerts

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// A bare IPv6 syslog host ("::1") must be bracketed when joined with the
// port. fmt.Sprintf("%s:%d") produced "::1:NNNN", which net.Dial rejects.
func TestSyslogIPv6Host(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- line
	}()

	target := SyslogTarget{Host: "::1", Port: port, Protocol: "tcp", Tag: "znas-test"}
	if err := sendSyslogMsg(target, "subj", "test_event", "details", "host1"); err != nil {
		t.Fatalf("sendSyslogMsg to [::1]: %v", err)
	}
	select {
	case line := <-got:
		if !strings.Contains(line, "event=test_event") {
			t.Fatalf("unexpected syslog payload: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog message received")
	}
}

func TestHostPortBracketsIPv6(t *testing.T) {
	cases := map[string]string{
		"::1":         "[::1]:514",
		"fd00::10":    "[fd00::10]:514",
		"192.168.2.5": "192.168.2.5:514",
		"syslog.lan":  "syslog.lan:514",
	}
	for host, want := range cases {
		if got := hostPort(host, 514); got != want {
			t.Errorf("hostPort(%q) = %q, want %q", host, got, want)
		}
		if _, _, err := net.SplitHostPort(hostPort(host, 514)); err != nil {
			t.Errorf("hostPort(%q) not dialable: %v", host, err)
		}
	}
}
