//go:build linux

package iptables

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func skipIfNoFirewalld(t *testing.T) {
	t.Helper()
	conn, err := dbus.SystemBus()
	if err != nil {
		t.Skipf("cannot connect to D-bus system bus: %v", err)
	}
	defer conn.Close()

	var zone string
	err = conn.Object(dbusInterface, dbusPath).Call(dbusInterface+".getDefaultZone", 0).Store(&zone)
	if err != nil {
		t.Skipf("firewalld is not running: %v", err)
	}
}

func TestFirewalldInit(t *testing.T) {
	skipIfNoFirewalld(t)
	if err := firewalldInit(); err != nil {
		t.Fatal(err)
	}
}

func TestPassthrough(t *testing.T) {
	skipIfNoFirewalld(t)
	rule1 := []string{
		"-i", "lo",
		"-p", "udp",
		"--dport", "123",
		"-j", "ACCEPT",
	}

	_, err := Passthrough(Iptables, append([]string{"-A"}, rule1...)...)
	if err != nil {
		t.Fatal(err)
	}
	if !GetIptable(IPv4).Exists(Filter, "INPUT", rule1...) {
		t.Fatal("rule1 does not exist")
	}
}
