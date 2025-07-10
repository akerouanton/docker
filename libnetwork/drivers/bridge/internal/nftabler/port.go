// FIXME(thaJeztah): remove once we are a module; the go:build directive prevents go from downgrading language version to go1.16:
//go:build go1.22 && linux

package nftabler

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
	"github.com/docker/docker/libnetwork/types"
)

type pbContext struct {
	table nftables.TableRef
	conf  firewaller.NetworkConfigFam
	ipv   firewaller.IPVersion
}

func (n *network) AddPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, true)
}

func (n *network) DelPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, false)
}

func (n *network) modPorts(ctx context.Context, pbs []types.PortBinding, enable bool) error {
	if n.config.Internal {
		return nil
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"bridge": n.config.IfName}))

	pbs4, pbs6 := splitByContainerFam(pbs)
	if n.fw.config.IPv4 && n.config.Config4.Prefix.IsValid() {
		pbc := pbContext{table: n.fw.table4, conf: n.config.Config4, ipv: firewaller.IPv4}
		if err := n.setPerPortRules(ctx, pbs4, pbc, enable); err != nil {
			return err
		}
	}
	if n.fw.config.IPv6 && n.config.Config6.Prefix.IsValid() {
		pbc := pbContext{table: n.fw.table6, conf: n.config.Config6, ipv: firewaller.IPv6}
		if err := n.setPerPortRules(ctx, pbs6, pbc, enable); err != nil {
			return err
		}
	}
	return nil
}

func splitByContainerFam(pbs []types.PortBinding) ([]types.PortBinding, []types.PortBinding) {
	var pbs4, pbs6 []types.PortBinding
	for _, pb := range pbs {
		if pb.IP.To4() != nil {
			pbs4 = append(pbs4, pb)
		} else {
			pbs6 = append(pbs6, pb)
		}
	}
	return pbs4, pbs6
}

func (n *network) setPerPortRules(ctx context.Context, pbs []types.PortBinding, pbc pbContext, enable bool) error {
	var rb nftables.RulesBuilder
	for _, pb := range pbs {
		// Rules for NATed and routed ports
		if !pbc.conf.Unprotected {
			rb.Append(n.setPerPortForwarding(pbc.table.Family(), pb)...)
		}

		// Routed and 6to4 port mappings aren't NATed
		if pb.HostPort == 0 || (pb.IP.To4() != nil) != (pb.HostIP.To4() != nil) {
			continue
		}

		// Rules for NATed ports
		rb.Append(n.setPerPortDNAT(pbc.table.Family(), pb)...)

		if n.fw.config.Hairpin {
			rb.Append(n.setPerPortHairpinMasq(pbc.table.Family(), pb)...)
		}

		// ::1 is non-routable, and thus can't be NATed.
		if pb.HostIP.IsLoopback() && pbc.ipv == firewaller.IPv4 {
			rb.Append(n.filterPortMappedOnLoopback(pb)...)
		}
	}

	if err := nftApply(ctx, pbc.table); err != nil {
		return fmt.Errorf("adding rules for bridge %s: %w", n.config.IfName, err)
	}
	return nil
}

func (n *network) setPerPortForwarding(fam nftables.Family, pb types.PortBinding) []nftables.Rule {
	var rb nftables.RulesBuilder

	// When more than one host port is mapped to a single container port, this will
	// generate the same rule for each host port. So, ignore duplicates when adding,
	// and missing rules when removing. (No ref-counting is currently needed because
	// when bindings are added or removed for an endpoint, they're all added or
	// removed. So, a rule that's added more than once will also be deleted more
	// than once.)
	//
	// TODO(robmry) - track port mappings, use that to edit nftables sets when bindings are added/removed.
	rb.AddRule(nftables.Rule{
		Chain: chainFilterFwdIn(n.config.IfName),
		Group: fwdInPortsRuleGroup,
		Expr: fmt.Sprintf("%s daddr %s %s dport %d counter accept",
			fam, pb.IP, pb.Proto, pb.Port),
	})

	return rb.Rules()
}

func (n *network) setPerPortDNAT(fam nftables.Family, pb types.PortBinding) []nftables.Rule {
	var rb nftables.RulesBuilder

	r := rb.AddRuleBuilder(nftables.RuleBuilder{Chain: natChain, Group: initialRuleGroup})
	if !n.fw.config.Hairpin {
		r.Writef("iifname != %s", n.config.IfName)
	}
	if fam == nftables.IPv6 {
		r.Write("ip6 saddr != fe80::/10")
	}
	if !pb.HostIP.IsUnspecified() {
		r.Writef("%s daddr %s", fam, pb.HostIP)
	}
	r.Writef("%s dport %d counter dnat to %s comment DNAT", pb.Proto, pb.HostPort, net.JoinHostPort(pb.IP.String(), strconv.Itoa(int(pb.Port))))

	return rb.Rules()
}

// setPerPortHairpinMasq allows containers to access their own published ports on the host
// when hairpin is enabled (no docker-proxy), by masquerading.
func (n *network) setPerPortHairpinMasq(fam nftables.Family, pb types.PortBinding) []nftables.Rule {
	var rb nftables.RulesBuilder
	// When more than one host port is mapped to a single container port, this will
	// generate the same rule for each host port. So, ignore duplicates when adding,
	// and missing rules when removing. (No ref-counting is currently needed because
	// when bindings are added or removed for an endpoint, they're all added or
	// removed. So, a rule that's added more than once will also be deleted more
	// than once.)
	//
	// TODO(robmry) - track port mappings, use that to edit nftables sets when bindings are added/removed.
	rb.AddRule(nftables.Rule{
		Chain: chainNatPostRtIn(n.config.IfName),
		Group: initialRuleGroup,
		Expr: fmt.Sprintf(
			`%s saddr %s %s daddr %s %s dport %d counter masquerade comment "MASQ TO OWN PORT"`,
			fam, pb.IP, fam, pb.IP, pb.Proto, pb.Port),
	})

	return rb.Rules()
}

// filterPortMappedOnLoopback adds a rule that drops remote connections to ports
// mapped to loopback addresses.
//
// This is a no-op if the portBinding is for IPv6 (IPv6 loopback address is
// non-routable), or over a network with gw_mode=routed (PBs in routed mode
// don't map ports on the host).
func (n *network) filterPortMappedOnLoopback(pb types.PortBinding) []nftables.Rule {
	var rb nftables.RulesBuilder
	if n.fw.config.WSL2Mirrored {
		rb.AddRule(nftables.Rule{
			Chain: rawPreroutingChain,
			Group: rawPreroutingPortsRuleGroup,
			Expr: fmt.Sprintf(
				`iifname loopback0 ip daddr %s %s dport %d counter accept comment "ACCEPT WSL2 LOOPBACK"`,
				pb.HostIP, pb.Proto, pb.HostPort,
			),
		})
	}

	rb.AddRule(nftables.Rule{
		Chain: rawPreroutingChain,
		Group: rawPreroutingPortsRuleGroup,
		Expr: fmt.Sprintf(
			`iifname != lo ip daddr %s %s dport %d counter drop comment "DROP REMOTE LOOPBACK"`,
			pb.HostIP, pb.Proto, pb.HostPort,
		),
	})

	return rb.Rules()
}
