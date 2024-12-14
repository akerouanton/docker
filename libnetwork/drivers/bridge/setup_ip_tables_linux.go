package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/containerd/log"
	"github.com/docker/docker/internal/nlwrap"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/fwipt"
	"github.com/docker/docker/libnetwork/iptables"
	"github.com/docker/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
)

func (n *bridgeNetwork) setupIP4Tables(config *networkConfiguration, i *bridgeInterface) error {
	d := n.driver
	d.Lock()
	driverConfig := d.config
	d.Unlock()

	// Sanity check.
	if !driverConfig.EnableIPTables {
		return errors.New("Cannot program chains, EnableIPTable is disabled")
	}

	maskedAddrv4 := &net.IPNet{
		IP:   i.bridgeIPv4.IP.Mask(i.bridgeIPv4.Mask),
		Mask: i.bridgeIPv4.Mask,
	}
	return n.setupIPTables(iptables.IPv4, maskedAddrv4, config, i)
}

func (n *bridgeNetwork) setupIP6Tables(config *networkConfiguration, i *bridgeInterface) error {
	d := n.driver
	d.Lock()
	driverConfig := d.config
	d.Unlock()

	// Sanity check.
	if !driverConfig.EnableIP6Tables {
		return errors.New("Cannot program chains, EnableIP6Tables is disabled")
	}

	maskedAddrv6 := &net.IPNet{
		IP:   i.bridgeIPv6.IP.Mask(i.bridgeIPv6.Mask),
		Mask: i.bridgeIPv6.Mask,
	}

	return n.setupIPTables(iptables.IPv6, maskedAddrv6, config, i)
}

func (n *bridgeNetwork) setupIPTables(ipVersion iptables.IPVersion, maskedAddr *net.IPNet, config *networkConfiguration, i *bridgeInterface) error {
	var err error

	d := n.driver
	d.Lock()
	driverConfig := d.config
	d.Unlock()

	// Pickup this configuration option from driver
	hairpinMode := !driverConfig.EnableUserlandProxy

	iptable := iptables.GetIptable(ipVersion)
	ipsetName := fwipt.IpsetExtBridges4
	if ipVersion == iptables.IPv6 {
		ipsetName = fwipt.IpsetExtBridges6
	}

	fwConf := n.firewallConfig(ipVersion)

	if config.Internal {
		if err = n.driver.fw.SetupInternalNetwork(fwConf, true); err != nil {
			return fmt.Errorf("Failed to Setup IP tables: %w", err)
		}
		n.registerIptCleanFunc(func() error {
			return n.driver.fw.SetupInternalNetwork(fwConf, false)
		})
	} else {
		if err = n.driver.fw.SetupNonInternalNetwork(fwConf, true); err != nil {
			return fmt.Errorf("Failed to Setup IP tables: %w", err)
		}
		n.registerIptCleanFunc(func() error {
			return n.driver.fw.SetupNonInternalNetwork(fwConf, true)
		})

		natChain, filterChain, err := n.getDriverChains(ipVersion)
		if err != nil {
			return fmt.Errorf("Failed to setup IP tables, cannot acquire chain info %w", err)
		}

		err = iptable.ProgramChain(natChain, config.BridgeName, hairpinMode, true)
		if err != nil {
			return fmt.Errorf("Failed to program NAT chain: %w", err)
		}

		err = iptable.ProgramChain(filterChain, config.BridgeName, hairpinMode, true)
		if err != nil {
			return fmt.Errorf("Failed to program FILTER chain: %w", err)
		}
		n.registerIptCleanFunc(func() error {
			return iptable.ProgramChain(filterChain, config.BridgeName, hairpinMode, false)
		})

		if err := n.setDefaultForwardRule(ipVersion, config.BridgeName); err != nil {
			return err
		}

		cidr, _ := maskedAddr.Mask.Size()
		if cidr == 0 {
			return fmt.Errorf("no CIDR for bridge %s addr %s", config.BridgeName, maskedAddr)
		}
		ipsetEntry := &netlink.IPSetEntry{
			IP:   maskedAddr.IP,
			CIDR: uint8(cidr),
		}
		if err := netlink.IpsetAdd(ipsetName, ipsetEntry); err != nil {
			return fmt.Errorf("failed to add bridge %s (%s) to ipset: %w",
				config.BridgeName, maskedAddr, err)
		}
		n.registerIptCleanFunc(func() error {
			return netlink.IpsetDel(ipsetName, ipsetEntry)
		})
	}
	return nil
}

func (n *bridgeNetwork) setDefaultForwardRule(
	ipVersion iptables.IPVersion,
	bridgeName string,
) error {
	// Normally, DROP anything that hasn't been ACCEPTed by a per-port/protocol
	// rule. This prevents direct access to un-mapped ports from remote hosts
	// that can route directly to the container's address (by setting up a
	// route via the host's address).
	action := "DROP"
	if n.gwMode(ipVersion).unprotected() {
		// If the user really wants to allow all access from the wider network,
		// explicitly ACCEPT anything so that the filter-FORWARD chain's
		// default policy can't interfere.
		action = "ACCEPT"
	}

	rule := iptRule{ipv: ipVersion, table: iptables.Filter, chain: fwipt.DockerChain, args: []string{
		"!", "-i", bridgeName,
		"-o", bridgeName,
		"-j", action,
	}}

	// Append to the filter table's DOCKER chain (the default rule must follow
	// per-port ACCEPT rules, which will be inserted at the top of the chain).
	if err := appendOrDelChainRule(rule, "DEFAULT FWD", true); err != nil {
		return fmt.Errorf("failed to add default-drop rule: %w", err)
	}
	n.registerIptCleanFunc(func() error {
		return appendOrDelChainRule(rule, "DEFAULT FWD", false)
	})
	return nil
}

type iptRule struct {
	ipv   iptables.IPVersion
	table iptables.Table
	chain string
	args  []string
}

// Exists returns true if the rule exists in the kernel.
func (r iptRule) Exists() bool {
	return iptables.GetIptable(r.ipv).Exists(r.table, r.chain, r.args...)
}

func (r iptRule) cmdArgs(op iptables.Action) []string {
	return append([]string{"-t", string(r.table), string(op), r.chain}, r.args...)
}

func (r iptRule) exec(op iptables.Action) error {
	return iptables.GetIptable(r.ipv).RawCombinedOutput(r.cmdArgs(op)...)
}

// Append appends the rule to the end of the chain. If the rule already exists anywhere in the
// chain, this is a no-op.
func (r iptRule) Append() error {
	if r.Exists() {
		return nil
	}
	return r.exec(iptables.Append)
}

// Insert inserts the rule at the head of the chain. If the rule already exists anywhere in the
// chain, this is a no-op.
func (r iptRule) Insert() error {
	if r.Exists() {
		return nil
	}
	return r.exec(iptables.Insert)
}

// Delete deletes the rule from the kernel. If the rule does not exist, this is a no-op.
func (r iptRule) Delete() error {
	if !r.Exists() {
		return nil
	}
	return r.exec(iptables.Delete)
}

func (r iptRule) String() string {
	cmd := append([]string{"iptables"}, r.cmdArgs("-A")...)
	if r.ipv == iptables.IPv6 {
		cmd[0] = "ip6tables"
	}
	return strings.Join(cmd, " ")
}

func programChainRule(rule iptRule, ruleDescr string, insert bool) error {
	operation := "disable"
	fn := rule.Delete
	if insert {
		operation = "enable"
		fn = rule.Insert
	}
	if err := fn(); err != nil {
		return fmt.Errorf("Unable to %s %s rule: %w", operation, ruleDescr, err)
	}
	return nil
}

func appendOrDelChainRule(rule iptRule, ruleDescr string, append bool) error {
	operation := "disable"
	fn := rule.Delete
	if append {
		operation = "enable"
		fn = rule.Append
	}
	if err := fn(); err != nil {
		return fmt.Errorf("Unable to %s %s rule: %w", operation, ruleDescr, err)
	}
	return nil
}

// Control Inter-Network Communication.
// Install rules only if they aren't present, remove only if they are.
// If this method returns an error, it doesn't roll back any rules it has added.
// No error is returned if rules cannot be removed (errors are just logged).
func setINC(version iptables.IPVersion, iface string, gwm gwMode, enable bool) (retErr error) {
	iptable := iptables.GetIptable(version)
	actionI, actionA := iptables.Insert, iptables.Append
	actionMsg := "add"
	if !enable {
		actionI, actionA = iptables.Delete, iptables.Delete
		actionMsg = "remove"
	}

	if gwm.routed() {
		// Anything is allowed into a routed network at this stage, so RETURN. Port
		// filtering rules in the DOCKER chain will drop anything that's not destined
		// for an open port.
		if err := iptable.ProgramRule(iptables.Filter, fwipt.IsolationChain1, actionI, []string{
			"-o", iface,
			"-j", "RETURN",
		}); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
			if enable {
				return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
			}
		}

		// Allow responses from the routed network into whichever network made the request.
		if err := iptable.ProgramRule(iptables.Filter, fwipt.IsolationChain1, actionI, []string{
			"-i", iface,
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
			"-j", "ACCEPT",
		}); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
			if enable {
				return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
			}
		}
	}

	if err := iptable.ProgramRule(iptables.Filter, fwipt.IsolationChain1, actionA, []string{
		"-i", iface,
		"!", "-o", iface,
		"-j", fwipt.IsolationChain2,
	}); err != nil {
		log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
		if enable {
			return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
		}
	}

	if err := iptable.ProgramRule(iptables.Filter, fwipt.IsolationChain2, actionI, []string{
		"-o", iface,
		"-j", "DROP",
	}); err != nil {
		log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
		if enable {
			return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
		}
	}

	return nil
}

// clearConntrackEntries flushes conntrack entries matching endpoint IP address
// or matching one of the exposed UDP port.
// In the first case, this could happen if packets were received by the host
// between userland proxy startup and iptables setup.
// In the latter case, this could happen if packets were received whereas there
// were nowhere to route them, as netfilter creates entries in such case.
// This is required because iptables NAT rules are evaluated by netfilter only
// when creating a new conntrack entry. When Docker latter adds NAT rules,
// netfilter ignore them for any packet matching a pre-existing conntrack entry.
// As such, we need to flush all those conntrack entries to make sure NAT rules
// are correctly applied to all packets.
// See: #8795, #44688 & #44742.
func clearConntrackEntries(nlh nlwrap.Handle, ep *bridgeEndpoint) {
	var ipv4List []net.IP
	var ipv6List []net.IP
	var udpPorts []uint16

	if ep.addr != nil {
		ipv4List = append(ipv4List, ep.addr.IP)
	}
	if ep.addrv6 != nil {
		ipv6List = append(ipv6List, ep.addrv6.IP)
	}
	for _, pb := range ep.portMapping {
		if pb.Proto == types.UDP {
			udpPorts = append(udpPorts, pb.HostPort)
		}
	}

	iptables.DeleteConntrackEntries(nlh, ipv4List, ipv6List)
	iptables.DeleteConntrackEntriesByPort(nlh, types.UDP, udpPorts)
}
