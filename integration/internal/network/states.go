package network

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/testutil/environment"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/poll"
)

// IsRemoved verifies the network is removed.
func IsRemoved(ctx context.Context, client client.NetworkAPIClient, networkID string) func(log poll.LogT) poll.Result {
	return func(log poll.LogT) poll.Result {
		_, err := client.NetworkInspect(ctx, networkID, types.NetworkInspectOptions{})
		if err == nil {
			return poll.Continue("waiting for network %s to be removed", networkID)
		}
		return poll.Success()
	}
}

func GetSubnet(ctx context.Context, t *testing.T, testEnv *environment.Execution, client client.NetworkAPIClient, networkID string) netip.Prefix {
	if networkID == "default" {
		if testEnv.DaemonInfo.OSType == "linux" {
			networkID = "bridge"
		} else if testEnv.DaemonInfo.OSType == "windows" {
			networkID = "nat"
		} else {
			panic(fmt.Sprintf("unsupported OSType = %s", testEnv.DaemonInfo.OSType))
		}
	}

	nw, err := client.NetworkInspect(ctx, networkID, types.NetworkInspectOptions{})
	assert.NilError(t, err)
	assert.Check(t, len(nw.IPAM.Config) > 0)

	p, err := netip.ParsePrefix(nw.IPAM.Config[0].Subnet)
	assert.NilError(t, err)

	return p
}
