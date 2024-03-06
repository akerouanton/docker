package driverapi

import (
	"net"
)

// EndpointDriver represents a driver capable of managing endpoints.
type EndpointDriver interface {
	Driver

	// CreateEndpoint invokes the driver method to create an endpoint passing
	// the network id, endpoint id, and a set of options that should be applied
	// to the endpoint. The driver is required to return a set of options, with
	// whatever it deems needed for the Join operation.
	CreateEndpoint(nid, eid string, opts EndpointOptions) (EndpointOptions, error)

	// DeleteEndpoint invokes the driver method to delete an endpoint
	// passing the network id and endpoint id.
	DeleteEndpoint(nid, eid string) error

	// EndpointOperInfo retrieves from the driver the operational data related to the specified endpoint
	EndpointOperInfo(nid, eid string) (map[string]interface{}, error)

	// Join method is invoked when a Sandbox is attached to an endpoint.
	Join(nid, eid string, sboxKey string, jinfo JoinInfo, options map[string]interface{}) error

	// Leave method is invoked when a Sandbox detaches from an endpoint.
	Leave(nid, eid string) error
}

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
