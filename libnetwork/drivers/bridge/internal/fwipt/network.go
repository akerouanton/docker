package fwipt

import (
	"context"
	"fmt"
	"net"

	"github.com/containerd/log"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/libnetwork/iptables"
)

type Network struct {
	BridgeName string     // BridgeName is the name of the bridge interface.
	BridgeAddr *net.IPNet // BridgeAddr is the address of the bridge interface, plus its mask.
	ICC        bool       // ICC indicates whether inter-container communications are allowed
	Hairpin    bool       // Hairpin indicates whether hairpinning should be used.
	Masquerade bool       // Masquerade indicates whether egress should be masqueraded.
	HostIP     net.IP     // HostIP is the IP address to use for egress and local ingress SNAT.
	Internal   bool       // Internal indicates whether egress is allowed on this bridge.
	IsNATed    bool       // IsNATed indicates whether containers are accessed through NAT or direct routing.
}

func (ipt *IPTables) SetupInternalNetwork(nw Network, insert bool) error {
	var version iptables.IPVersion
	var inDropRule, outDropRule iptRule

	// Either add or remove the interface from the firewalld zone, if firewalld is running.
	if insert {
		if err := iptables.AddInterfaceFirewalld(nw.BridgeName); err != nil {
			return err
		}
	} else {
		if err := iptables.DelInterfaceFirewalld(nw.BridgeName); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
	}

	if nw.BridgeAddr.IP.To4() != nil {
		version = iptables.IPv4
		inDropRule = iptRule{
			ipv:   version,
			table: iptables.Filter,
			chain: IsolationChain1,
			args:  []string{"-i", nw.BridgeName, "!", "-d", nw.BridgeAddr.String(), "-j", "DROP"},
		}
		outDropRule = iptRule{
			ipv:   version,
			table: iptables.Filter,
			chain: IsolationChain1,
			args:  []string{"-o", nw.BridgeName, "!", "-s", nw.BridgeAddr.String(), "-j", "DROP"},
		}
	} else {
		version = iptables.IPv6
		inDropRule = iptRule{
			ipv:   version,
			table: iptables.Filter,
			chain: IsolationChain1,
			args:  []string{"-i", nw.BridgeName, "!", "-o", nw.BridgeName, "!", "-d", nw.BridgeAddr.String(), "-j", "DROP"},
		}
		outDropRule = iptRule{
			ipv:   version,
			table: iptables.Filter,
			chain: IsolationChain1,
			args:  []string{"!", "-i", nw.BridgeName, "-o", nw.BridgeName, "!", "-s", nw.BridgeAddr.String(), "-j", "DROP"},
		}
	}

	if err := programChainRule(inDropRule, "DROP INCOMING", insert); err != nil {
		return err
	}
	if err := programChainRule(outDropRule, "DROP OUTGOING", insert); err != nil {
		return err
	}

	// Set Inter Container Communication.
	return setIcc(version, nw, insert)
}

func setIcc(version iptables.IPVersion, nw Network, insert bool) error {
	args := []string{"-i", nw.BridgeName, "-o", nw.BridgeName, "-j"}
	acceptRule := iptRule{ipv: version, table: iptables.Filter, chain: "FORWARD", args: append(args, "ACCEPT")}
	dropRule := iptRule{ipv: version, table: iptables.Filter, chain: "FORWARD", args: append(args, "DROP")}

	// The accept rule is no longer required for a bridge with external connectivity, because
	// ICC traffic is allowed by the outgoing-packets rule created by setupIptablesInternal.
	// The accept rule is still required for a --internal network because it has no outgoing
	// rule. If insert and the rule is not required, an ACCEPT rule for an external network
	// may have been left behind by an older version of the daemon so, delete it.
	if insert && nw.ICC && nw.Internal {
		if err := acceptRule.Append(); err != nil {
			return fmt.Errorf("Unable to allow intercontainer communication: %w", err)
		}
	} else {
		if err := acceptRule.Delete(); err != nil {
			log.G(context.TODO()).WithError(err).Warn("Failed to delete legacy ICC accept rule")
		}
	}

	if insert && !nw.ICC {
		if err := dropRule.Append(); err != nil {
			return fmt.Errorf("Unable to prevent intercontainer communication: %w", err)
		}
	} else {
		if err := dropRule.Delete(); err != nil {
			log.G(context.TODO()).WithError(err).Warn("Failed to delete ICC drop rule")
		}
	}
	return nil
}

func (ipt *IPTables) SetupNonInternalNetwork(nw Network, enable bool) error {
	ipVer := iptables.IPv4
	if nw.BridgeAddr.IP.To4() == nil {
		ipVer = iptables.IPv6
	}

	var natArgs, hpNatArgs []string
	if nw.HostIP != nil {
		// The user wants IPv4/IPv6 SNAT with the given address.
		hostAddr := nw.HostIP.String()
		natArgs = []string{"-s", nw.BridgeAddr.String(), "!", "-o", nw.BridgeName, "-j", "SNAT", "--to-source", hostAddr}
		hpNatArgs = []string{"-m", "addrtype", "--src-type", "LOCAL", "-o", nw.BridgeName, "-j", "SNAT", "--to-source", hostAddr}
	} else {
		// Use MASQUERADE, which picks the src-ip based on next-hop from the route table
		natArgs = []string{"-s", nw.BridgeAddr.String(), "!", "-o", nw.BridgeName, "-j", "MASQUERADE"}
		hpNatArgs = []string{"-m", "addrtype", "--src-type", "LOCAL", "-o", nw.BridgeName, "-j", "MASQUERADE"}
	}
	natRule := iptRule{ipv: ipVer, table: iptables.Nat, chain: "POSTROUTING", args: natArgs}
	hpNatRule := iptRule{ipv: ipVer, table: iptables.Nat, chain: "POSTROUTING", args: hpNatArgs}

	// Set NAT.
	if nw.IsNATed && nw.Masquerade {
		if err := programChainRule(natRule, "NAT", enable); err != nil {
			return err
		}
	}
	if !nw.IsNATed || (nw.Masquerade && !nw.Hairpin) {
		skipDNAT := iptRule{ipv: ipVer, table: iptables.Nat, chain: DockerChain, args: []string{
			"-i", nw.BridgeName,
			"-j", "RETURN",
		}}
		if err := programChainRule(skipDNAT, "SKIP DNAT", enable); err != nil {
			return err
		}
	}

	// In hairpin mode, masquerade traffic from localhost. If hairpin is disabled or if we're tearing down
	// that bridge, make sure the iptables rule isn't lying around.
	if err := programChainRule(hpNatRule, "MASQ LOCAL HOST", enable && nw.Hairpin); err != nil {
		return err
	}

	// Set Inter Container Communication.
	if err := setIcc(ipVer, nw, enable); err != nil {
		return err
	}

	// Allow ICMP in routed mode.
	if !nw.IsNATed {
		if err := setICMP(ipVer, nw.BridgeName, enable); err != nil {
			return err
		}
	}

	// Handle outgoing packets. This rule was previously added unconditionally
	// to ACCEPT packets that weren't ICC - an extra rule was needed to enable
	// ICC if needed. Those rules are now combined. So, outRuleNoICC is only
	// needed for ICC=false, along with the DROP rule for ICC added by setIcc.
	outRuleNoICC := iptRule{ipv: ipVer, table: iptables.Filter, chain: "FORWARD", args: []string{
		"-i", nw.BridgeName,
		"!", "-o", nw.BridgeName,
		"-j", "ACCEPT",
	}}
	if nw.ICC {
		// Remove the legacy rule for ICC (which didn't accept outgoing traffic), if one has been
		// left behind by an old daemon.
		if err := outRuleNoICC.Delete(); err != nil {
			return err
		}
		// Accept outgoing traffic to anywhere, including other containers on this bridge.
		outRuleICC := iptRule{ipv: ipVer, table: iptables.Filter, chain: "FORWARD", args: []string{
			"-i", nw.BridgeName,
			"-j", "ACCEPT",
		}}
		if err := appendOrDelChainRule(outRuleICC, "ACCEPT OUTGOING", enable); err != nil {
			return err
		}
	} else {
		// Accept outgoing traffic to anywhere, apart from other containers on this bridge.
		// setIcc added a DROP rule for ICC traffic.
		if err := appendOrDelChainRule(outRuleNoICC, "ACCEPT NON_ICC OUTGOING", enable); err != nil {
			return err
		}
	}

	return nil
}

func setICMP(ipv iptables.IPVersion, bridgeName string, enable bool) error {
	icmpProto := "icmp"
	if ipv == iptables.IPv6 {
		icmpProto = "icmpv6"
	}
	icmpRule := iptRule{ipv: ipv, table: iptables.Filter, chain: DockerChain, args: []string{
		"-o", bridgeName,
		"-p", icmpProto,
		"-j", "ACCEPT",
	}}
	return appendOrDelChainRule(icmpRule, "ICMP", enable)
}
