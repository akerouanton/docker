package fwipt

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
