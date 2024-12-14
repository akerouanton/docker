package fwipt

import (
	"testing"

	"github.com/docker/docker/internal/testutils/netnsutils"
	"github.com/docker/docker/libnetwork/iptables"
	"golang.org/x/sys/unix"
	"gotest.tools/v3/assert"
)

func TestCleanupIptableRules(t *testing.T) {
	defer netnsutils.SetupTestOSContext(t)()
	bridgeChains := []struct {
		name       string
		table      iptables.Table
		expRemoved bool
	}{
		{name: DockerChain, table: iptables.Nat, expRemoved: true},
		// The filter-FORWARD chain has references to DockerChain and IsolationChain1,
		// so the chains won't be removed - but they should be flushed. (This has
		// long/always been the case for the daemon, its filter-FORWARD rules aren't
		// removed.)
		{name: DockerChain, table: iptables.Filter},
		{name: IsolationChain1, table: iptables.Filter},
	}

	ipVersions := []iptables.IPVersion{iptables.IPv4, iptables.IPv6}
	configs := map[iptables.IPVersion]Config{
		iptables.IPv4: {EnableV4: true},
		iptables.IPv6: {EnableV6: true},
	}

	assert.NilError(t, setupHashNetIpset(IpsetExtBridges4, unix.AF_INET))
	assert.NilError(t, setupHashNetIpset(IpsetExtBridges6, unix.AF_INET6))

	for _, version := range ipVersions {
		_, _, _, _, err := setupIPChains(configs[version], version)
		assert.NilError(t, err, "version:%s", version)

		iptable := iptables.GetIptable(version)
		for _, chainInfo := range bridgeChains {
			exists := iptable.ExistChain(chainInfo.name, chainInfo.table)
			assert.Check(t, exists, "version:%s chain:%s table:%v",
				version, chainInfo.name, chainInfo.table)
		}

		// Insert RETURN rules so that there's something to flush.
		for _, chainInfo := range bridgeChains {
			out, err := iptable.Raw("-t", string(chainInfo.table), "-A", chainInfo.name, "-j", "RETURN")
			assert.NilError(t, err, "version:%s chain:%s table:%v out:%s",
				version, chainInfo.name, chainInfo.table, out)
		}

		removeIPChains(version)

		for _, chainInfo := range bridgeChains {
			exists := iptable.Exists(chainInfo.table, chainInfo.name, "-A", chainInfo.name, "-j", "RETURN")
			assert.Check(t, !exists, "version:%s chain:%s table:%v",
				version, chainInfo.name, chainInfo.table)
			if chainInfo.expRemoved {
				exists := iptable.ExistChain(chainInfo.name, chainInfo.table)
				assert.Check(t, !exists, "version:%s chain:%s table:%v",
					version, chainInfo.name, chainInfo.table)
			}
		}
	}
}
