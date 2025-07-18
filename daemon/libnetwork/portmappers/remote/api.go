package remote

import (
	"net/netip"

	"github.com/moby/moby/v2/daemon/libnetwork/types"
)

// MapPortsRequest is the API request sent to the PortMapper plugin to map a port.
type MapPortsRequest struct {
	// Reqs is a group of port bindings that should get the same port assigned
	// when an ephemeral port, or a port range is requested. Each Reqs should
	// yield an independent PortBinding.
	Reqs []PortBindingReq

	// Labels is a set of opaque, user-specified freeform labels that can be
	// used to tweak how the port-mapper behaves.
	Labels map[string]string
}

type PortBindingReq struct {
	Proto types.Protocol

	// BackendIP is the unmapped IP address of the backend service (e.g. container)
	// to map.
	BackendIP netip.Addr
	// BackendPort is the port of the backend service (i.e. container) to map.
	BackendPort uint16

	// FrontendIP is the unmapped IP address of the frontend service (e.g. container)
	// to map.
	FrontendIP netip.Addr
	// FrontendPort is either an exact port, an ephemeral port (= 0), or the start
	// of a port range.
	FrontendPort uint16
	// FrontendPortEnd should be the same as FrontendPort when an exact or ephemeral
	// port is requested. Otherwise, it should be the end of the port range.
	FrontendPortEnd uint16
}

// MapPortsResponse is the response returned by portmapper plugins after processing
// a MapPortsRequest.
type MapPortsResponse struct {
	PortBindings []PortBinding
	Err          string
}

// PortBinding represents a port mapped by the portmapper plugin. When the plugin
// fails to fulfill a PortBindingReq, it returns a PortBinding with all frontend
// and backend fields set, and an Error.
type PortBinding struct {
	Proto types.Protocol

	BackendIP   netip.Addr
	BackendPort uint16

	FrontendIP netip.Addr
	// FrontendPort is the frontend port picked by the PortMapper when an
	// ephemeral port, or a port range was specified in the request. Otherwise,
	// it's the exact FrontendPort requested.
	FrontendPort uint16

	// DiscardReq is returned when the PortBindingReq can't be fulfilled, but
	// the driver deems it's not a fatal error.
	DiscardReq bool

	// Error indicates the reason why this port binding was discarded. This
	// error is logged.
	Error *string
}

type UnmapPortsRequest struct {
	PortBindings []PortBinding
	Labels       map[string]string
}
