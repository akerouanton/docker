package driverapi

import (
	"net"

	"github.com/docker/docker/libnetwork/types"
)

// EndpointOptions represents the set of options that libnetwork request a
// driver to apply to an Endpoint.
type EndpointOptions struct {
	// MACAddress is the MAC address that should be assigned to this interface.
	MACAddress net.HardwareAddr
	// Addr is the IPv4 address that should be assigned to this interface.
	Addr *net.IPNet
	// AddrV6 is the IPv6 address that should be assigned to this interface.
	AddrV6 *net.IPNet
	// LLAddrs is a list of v4/v6 link-local addresses that should be assigned to this endpoint.
	LLAddrs []*net.IPNet
	// DriverOpts is a map of opaque driver options.
	DriverOpts map[string]interface{}
}

type JoinOptions struct {
	EndpointOptions
	// PortMappings as a Join option is only used by Windows drivers. The linux
	// bridge driver will set port mappings during the ProgramExternalConnectivity
	// operation.
	PortMappings []types.PortBinding
	// DriverOpts is a map of opaque driver options.
	DriverOpts map[string]interface{}
}

// EndpointInterface holds interface addresses bound to the endpoint.
type EndpointInterface struct {
	// MACAddress is the MAC address assigned to this interface.
	MACAddress net.HardwareAddr
	// Addr is the IPv4 address assigned to this interface.
	Addr *net.IPNet
	// AddrV6 is the IPv6 address assigned to this interface.
	AddrV6 *net.IPNet
	// LLAddrs is a list of v4/v6 link-local addresses assigned to this endpoint.
	LLAddrs []*net.IPNet
	// SrcName is the name of the interface on the host.
	SrcName string
	// DstPrefix is the name prefix for the interface within the container.
	DstPrefix string
	// Gateway is the IPv4 address of the gateway made available by this
	// endpoint.
	Gateway net.IP
	// GatewayV6 is the IPv6 address of the gateway made available by this
	// endpoint.
	GatewayV6 net.IP
	// Routes is a list of routes provided by an endpoint to a Sandbox.
	Routes []types.Route
	// DisableGatewayService indicates whether this endpoint requests the
	// Sandbox to be disconnected from
	DisableGatewayService bool
	GossipEntry           GossipEntry
}

type ConnectivityOptions struct {
	// TODO(aker): ditch this field once we drop support for legacy links.
	LegacyLinks types.LegacyLinks
	// ExposedPorts is only used by the bridge driver to support legacy links.
	// TODO(aker): ditch this field once we drop support for legacy links.
	ExposedPorts []types.TransportPort
	PortMappings []types.PortBinding
}

// GossipEntry represents a k/v entry that should be added to the gossip db.
type GossipEntry struct {
	TableName string
	Key       string
	Value     []byte
}
