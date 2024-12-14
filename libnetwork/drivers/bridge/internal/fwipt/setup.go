package fwipt

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/log"
	"github.com/docker/docker/internal/modprobe"
	"github.com/docker/docker/libnetwork/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Initialize iptables -- start by removing existing rules managed by dockerd,
// then recreate them.
func (ipt *IPTables) Initialize() error {
	var err error

	if ipt.config.EnableV4 {
		removeIPChains(iptables.IPv4)

		if err := setupHashNetIpset(IpsetExtBridges4, unix.AF_INET); err != nil {
			return err
		}

		ipt.NatChain, ipt.FilterChain, err = setupIPChains(ipt.config, iptables.IPv4)
		if err != nil {
			return err
		}

		// Make sure on firewall reload, first thing being re-played is chains creation
		iptables.OnReloaded(func() {
			log.G(context.TODO()).Debugf("Recreating iptables chains on firewall reload")
			if _, _, _, _, err := setupIPChains(ipt.config, iptables.IPv4); err != nil {
				log.G(context.TODO()).WithError(err).Error("Error reloading iptables chains")
			}
		})
	}

	if ipt.config.EnableV6 {
		if err := modprobe.LoadModules(context.TODO(), func() error {
			iptable := iptables.GetIptable(iptables.IPv6)
			_, err := iptable.Raw("-t", "filter", "-n", "-L", "FORWARD")
			return err
		}, "ip6_tables"); err != nil {
			log.G(context.TODO()).WithError(err).Debug("Loading ip6_tables")
		}

		removeIPChains(iptables.IPv6)

		if err := setupHashNetIpset(IpsetExtBridges6, unix.AF_INET6); err != nil {
			// Continue, IPv4 will work (as below).
			log.G(context.TODO()).WithError(err).Warn("ip6tables is enabled, but cannot set up IPv6 ipset")
		} else {
			ipt.NatChainV6, ipt.FilterChainV6, ipt.IsolationChain1V6, ipt.IsolationChain2V6, err = setupIPChains(ipt.config, iptables.IPv6)
			if err != nil {
				// If the chains couldn't be set up, it's probably because the kernel has no IPv6
				// support, or it doesn't have module ip6_tables loaded. It won't be possible to
				// create IPv6 networks without enabling ip6_tables in the kernel, or disabling
				// ip6tables in the daemon config. But, allow the daemon to start because IPv4
				// will work. So, log the problem, and continue.
				log.G(context.TODO()).WithError(err).Warn("ip6tables is enabled, but cannot set up ip6tables chains")
			} else {
				// Make sure on firewall reload, first thing being re-played is chains creation
				iptables.OnReloaded(func() {
					log.G(context.TODO()).Debugf("Recreating ip6tables chains on firewall reload")
					if _, _, _, _, err := setupIPChains(ipt.config, iptables.IPv6); err != nil {
						log.G(context.TODO()).WithError(err).Error("Error reloading ip6tables chains")
					}
				})
			}
		}
	}

	return nil
}

// Obsolete chain from previous docker versions
const oldIsolationChain = "DOCKER-ISOLATION"

func removeIPChains(version iptables.IPVersion) {
	ipt := iptables.GetIptable(version)

	// Remove obsolete rules from default chains
	ipt.ProgramRule(iptables.Filter, "FORWARD", iptables.Delete, []string{"-j", oldIsolationChain})

	// Remove chains
	for _, chainInfo := range []iptables.ChainInfo{
		{Name: DockerChain, Table: iptables.Nat, IPVersion: version},
		{Name: DockerChain, Table: iptables.Filter, IPVersion: version},
		{Name: IsolationChain1, Table: iptables.Filter, IPVersion: version},
		{Name: IsolationChain2, Table: iptables.Filter, IPVersion: version},
		{Name: oldIsolationChain, Table: iptables.Filter, IPVersion: version},
	} {
		if err := chainInfo.Remove(); err != nil {
			log.G(context.TODO()).Warnf("Failed to remove existing iptables entries in table %s chain %s : %v", chainInfo.Table, chainInfo.Name, err)
		}
	}
}

func setupHashNetIpset(name string, family uint8) error {
	if err := netlink.IpsetCreate(name, "hash:net", netlink.IpsetCreateOptions{
		Replace: true,
		Family:  family,
	}); err != nil {
		return err
	}
	if err := netlink.IpsetFlush(name); err != nil {
		return err
	}
	return nil
}

func setupIPChains(config Config, version iptables.IPVersion) (natChain *iptables.ChainInfo, filterChain *iptables.ChainInfo, isolationChain1 *iptables.ChainInfo, isolationChain2 *iptables.ChainInfo, retErr error) {
	// Sanity check.
	if version == iptables.IPv4 && !config.EnableV4 {
		return nil, nil, nil, nil, errors.New("cannot create new chains, iptables is disabled")
	}
	if version == iptables.IPv6 && !config.EnableV6 {
		return nil, nil, nil, nil, errors.New("cannot create new chains, ip6tables is disabled")
	}

	iptable := iptables.GetIptable(version)

	natChain, err := iptable.NewChain(DockerChain, iptables.Nat)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create NAT chain %s: %v", DockerChain, err)
	}
	defer func() {
		if retErr != nil {
			if err := iptable.RemoveExistingChain(DockerChain, iptables.Nat); err != nil {
				log.G(context.TODO()).Warnf("failed on removing iptables NAT chain %s on cleanup: %v", DockerChain, err)
			}
		}
	}()

	filterChain, err = iptable.NewChain(DockerChain, iptables.Filter)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create FILTER chain %s: %v", DockerChain, err)
	}
	defer func() {
		if err != nil {
			if err := iptable.RemoveExistingChain(DockerChain, iptables.Filter); err != nil {
				log.G(context.TODO()).Warnf("failed on removing iptables FILTER chain %s on cleanup: %v", DockerChain, err)
			}
		}
	}()

	isolationChain1, err = iptable.NewChain(IsolationChain1, iptables.Filter)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create FILTER isolation chain: %v", err)
	}
	defer func() {
		if retErr != nil {
			if err := iptable.RemoveExistingChain(IsolationChain1, iptables.Filter); err != nil {
				log.G(context.TODO()).Warnf("failed on removing iptables FILTER chain %s on cleanup: %v", IsolationChain1, err)
			}
		}
	}()

	isolationChain2, err = iptable.NewChain(IsolationChain2, iptables.Filter)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create FILTER isolation chain: %v", err)
	}
	defer func() {
		if retErr != nil {
			if err := iptable.RemoveExistingChain(IsolationChain2, iptables.Filter); err != nil {
				log.G(context.TODO()).Warnf("failed on removing iptables FILTER chain %s on cleanup: %v", IsolationChain2, err)
			}
		}
	}()

	// Make sure the filter-FORWARD chain has rules to accept related packets and
	// jump to the isolation and docker chains. (Re-)insert at the top of the table,
	// in reverse order.
	ipsetName := IpsetExtBridges4
	if version == iptables.IPv6 {
		ipsetName = IpsetExtBridges6
	}
	if err := iptable.EnsureJumpRule("FORWARD", DockerChain,
		"-m", "set", "--match-set", ipsetName, "dst"); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := iptable.EnsureJumpRule("FORWARD", IsolationChain1); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := iptable.EnsureJumpRule("FORWARD", "ACCEPT",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
	); err != nil {
		return nil, nil, nil, nil, err
	}

	if err := mirroredWSL2Workaround(config, version); err != nil {
		return nil, nil, nil, nil, err
	}

	return natChain, filterChain, isolationChain1, isolationChain2, nil
}
