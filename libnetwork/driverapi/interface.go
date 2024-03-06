package driverapi

import (
	"net"
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
