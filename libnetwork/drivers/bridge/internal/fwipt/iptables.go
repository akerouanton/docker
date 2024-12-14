package fwipt

import (
	"fmt"
	"strings"

	"github.com/docker/docker/libnetwork/iptables"
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

	// IpsetExtBridges4 and IpsetExtBridges6 are ipset names for IPv4 and IPv6
	// bridge subnets that don't belong to --internal networks.
	IpsetExtBridges4 = "docker-ext-bridges-v4"
	IpsetExtBridges6 = "docker-ext-bridges-v6"
)

type IPTables struct {
	config Config

	NatChain      *iptables.ChainInfo
	FilterChain   *iptables.ChainInfo
	NatChainV6    *iptables.ChainInfo
	FilterChainV6 *iptables.ChainInfo
}

type Config struct {
	EnableV4, EnableV6   bool
	EnableWSL2Workaround bool
}

func New(config Config) *IPTables {
	return &IPTables{
		config: config,
	}
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
