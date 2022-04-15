package fwiptables

import (
	"fmt"
	"github.com/docker/docker/libnetwork/firewall"
	"github.com/docker/docker/libnetwork/firewallapi"
	"github.com/docker/docker/libnetwork/iptables"
)

const (
	// outputChain used for docker embed dns
	outputChain = "DOCKER_OUTPUT"
	//postroutingchain used for docker embed dns
	postroutingchain = "DOCKER_POSTROUTING"
)

// DockerChain: DOCKER iptable chain name
const (
	DockerChain = "DOCKER"
	// Isolation between bridge networks is achieved in two stages by means
	// of the following two chains in the filter table. The first chain matches
	// on the source interface being a bridge network's bridge and the
	// destination being a different interface. A positive match leads to the
	// second isolation chain. No match returns to the parent chain. The second
	// isolation chain matches on destination interface being a bridge network's
	// bridge. A positive match identifies a packet originated from one bridge
	// network's bridge destined to another bridge network's bridge and will
	// result in the packet being dropped. No match returns to the parent chain.
	IsolationChain1 = "DOCKER-ISOLATION-STAGE-1"
	IsolationChain2 = "DOCKER-ISOLATION-STAGE-2"
)

type IPTablesFirewall struct {}

func New() firewall.Firewall {
	return IPTablesFirewall{}
}

func (fw IPTablesFirewall) SetupRootNS() error {
	return nil
}

func (fw IPTablesFirewall) SetupContainerNS(resolverIP string) error {
	return nil
}

func (fw IPTablesFirewall) AddResolverConnectivity(protocol firewall.Protocol, dnsPort, resolverIP, resolverPort string) error {
	table := iptables.GetTable(iptables.IPv4)

	// TODO(aker): move these line to an "init container netns" method
	table.AddJumpRuleForIP(firewallapi.Nat, "OUTPUT", outputChain, resolverIP)
	table.AddJumpRuleForIP(firewallapi.Nat, "POSTROUTING", outputChain, resolverIP)

	table.AddDNATwithPort(firewallapi.Nat, outputChain, resolverIP, "udp", dnsPort, fmt.Sprintf("%s:%s", resolverIP, resolverPort))
	table.ADDSNATwithPort(firewallapi.Nat, postroutingchain, resolverIP, "tcp", resolverPort, dnsPort)

	return nil
}

func modeToIPVersions(mode firewall.Mode) []iptables.IPVersion {
	switch mode {
	case firewall.IPv4:
		return []iptables.IPVersion{iptables.IPv4}
	case firewall.IPv6:
		return []iptables.IPVersion{iptables.IPv6}
	case firewall.DualStack:
		return []iptables.IPVersion{iptables.IPv4, iptables.IPv6}
	}

	panic("mode (%d) is neither IPv4, IPv6 nor DualStack")
}

func interNetworkConnectivityRules(iface string) [][]string {
	return [][]string{
		{"-i", iface, "!", "-o", iface, "-j", IsolationChain2},
		{"-o", iface, "-j", "DROP"},
	}
}

func (fw IPTablesFirewall) AddInterNetworkConnectivity(mode firewall.Mode, iface string) error {
	for _, version := range modeToIPVersions(mode) {
		table := iptables.GetTable(version)
		rules := interNetworkConnectivityRules(iface)

		// TODO(aker): log errors & rollback when something goes wrong
		table.ProgramRule(firewallapi.Filter, IsolationChain1, iptables.Insert, rules[0])
		table.ProgramRule(firewallapi.Filter, IsolationChain2, iptables.Insert, rules[1])

		// TODO(aker)
		/* msg := fmt.Sprintf("unable to %s inter-network communication rule: %v", actionMsg, err)
		// Rollback the rule installed on first chain
		logrus.Warnf("Failed to rollback firewall rule after failure (%v): %v", err, err2)
		return fmt.Errorf(msg) */
	}

	return nil
}

func (fw IPTablesFirewall) RemoveInterNetworkConnectivity(mode firewall.Mode, bridgeIface string) error {
	for _, version := range modeToIPVersions(mode) {
		table := iptables.GetTable(version)
		rules := interNetworkConnectivityRules(bridgeIface)

		// TODO(aker): log errors & rollback when something goes wrong
		table.DeleteRule(firewallapi.Filter, IsolationChain1, rules[0])
		table.DeleteRule(firewallapi.Filter, IsolationChain2, rules[1])

		// TODO(aker)
		/* logrus.Warn(fmt.Sprintf("unable to %s inter-network communication rule: %v", actionMsg, err)) */
	}

	return nil
}

func (fw IPTablesFirewall) AllowICC(mode firewall.Mode, bridgeIface string) error {
	rule := []string{"-i", bridgeIface, "-o", bridgeIface, "-j"}
	acceptRule := append(rule, "ACCEPT")
	dropRule := append(rule, "DROP")

	for _, version := range modeToIPVersions(mode) {
		table := iptables.GetTable(version)

		table.DeleteRule(version, "FORWARD", dropRule...)

		if table.Exists("FORWARD", acceptRule...) {
			continue
		}

		if err := table.ProgramRule("FORWARD", iptables.Insert, acceptRule); err != nil {
			return fmt.Errorf("Unable to allow intercontainer communication: %s", err.Error())
		}
	}

	return nil
}

func (fw IPTablesFirewall) DenyICC(mode firewall.Mode, bridgeIface string) error {
	rule := []string{"-i", bridgeIface, "-o", bridgeIface, "-j"}
	acceptRule := append(rule, "ACCEPT")
	dropRule := append(rule, "DROP")

	for _, version := range modeToIPVersions(mode) {
		table := iptables.GetTable(version)

		table.DeleteRule(version, "FORWARD", acceptRule...)

		if table.Exists("FORWARD", dropRule...) {
			continue
		}

		if err := table.ProgramRule("FORWARD", iptables.Append, dropRule); err != nil {
			return fmt.Errorf("Unable to allow intercontainer communication: %s", err.Error())
		}
	}

	return nil
}

func (fw IPTablesFirewall) CleanupICC(mode firewall.Mode, bridgeIface string) error {
	rule := []string{"-i", bridgeIface, "-o", bridgeIface, "-j"}
	acceptRule := append(rule, "ACCEPT")
	dropRule := append(rule, "DROP")

	for _, version := range modeToIPVersions(mode) {
		table := iptables.GetTable(version)

		if table.Exists("FORWARD", dropRule...) {
			table.Raw(append([]string{"-D", "FORWARD"}, dropRule...)...)
		}
		if table.Exists("FORWARD", acceptRule...) {
			table.Raw(append([]string{"-D", "FORWARD"}, acceptRule...)...)
		}
	}

	return nil
}
