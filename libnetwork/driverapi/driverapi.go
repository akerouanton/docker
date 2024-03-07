package driverapi

import (
	"net"
)

// NetworkPluginEndpointType represents the Endpoint Type used by Plugin system
const NetworkPluginEndpointType = "NetworkDriver"

// Driver is an interface that every plugin driver needs to implement.
type Driver interface {
	// NetworkAllocate invokes the driver method to allocate network
	// specific resources passing network id and network specific config.
	// It returns a key,value pair of network specific driver allocations
	// to the caller.
	NetworkAllocate(nid string, options map[string]string, ipV4Data, ipV6Data []IPAMData) (map[string]string, error)

	// NetworkFree invokes the driver method to free network specific resources
	// associated with a given network id.
	NetworkFree(nid string) error

	// CreateNetwork invokes the driver method to create a network
	// passing the network id and network specific config. The
	// config mechanism will eventually be replaced with labels
	// which are yet to be introduced. The driver can return a
	// list of table names for which it is interested in receiving
	// notification when a CRUD operation is performed on any
	// entry in that table. This will be ignored for local scope
	// drivers.
	CreateNetwork(nid string, options map[string]interface{}, nInfo NetworkInfo, ipV4Data, ipV6Data []IPAMData) error

	// DeleteNetwork invokes the driver method to delete network passing
	// the network id.
	DeleteNetwork(nid string) error

	// ProgramExternalConnectivity invokes the driver method which does the necessary
	// programming to allow the external connectivity dictated by the passed options
	ProgramExternalConnectivity(nid, eid string, options map[string]interface{}) error

	// RevokeExternalConnectivity asks the driver to remove any external connectivity
	// programming that was done so far
	RevokeExternalConnectivity(nid, eid string) error

	// EventNotify notifies the driver when a CRUD operation has
	// happened on a table of its interest as soon as this node
	// receives such an event in the gossip layer. This method is
	// only invoked for the global scope driver.
	EventNotify(event EventType, nid string, tableName string, key string, value []byte)

	// DecodeTableEntry passes the driver a key, value pair from table it registered
	// with libnetwork. Driver should return {object ID, map[string]string} tuple.
	// If DecodeTableEntry is called for a table associated with NetworkObject or
	// EndpointObject the return object ID should be the network id or endpoint id
	// associated with that entry. map should have information about the object that
	// can be presented to the user.
	// For example: overlay driver returns the VTEP IP of the host that has the endpoint
	// which is shown in 'network inspect --verbose'
	DecodeTableEntry(tablename string, key string, value []byte) (string, map[string]string)

	// Type returns the type of this driver, the network type this driver manages
	Type() string

	// IsBuiltIn returns true if it is a built-in driver
	IsBuiltIn() bool
}

// EndpointDriver represents a driver capable of managing endpoints.
type EndpointDriver interface {
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

	// Join method is invoked when an endpoint joins a sandbox.
	Join(nid, eid, sboxKey string, opts JoinOptions) (EndpointInterface, error)

	// Leave method is invoked when a Sandbox detaches from an endpoint.
	Leave(nid, eid string) error
}

// NetworkInfo provides a go interface for drivers to provide network
// specific information to libnetwork.
type NetworkInfo interface {
	// TableEventRegister registers driver interest in a given
	// table name.
	TableEventRegister(tableName string, objType ObjectType) error

	// UpdateIpamConfig updates the networks IPAM configuration
	// based on information from the driver.  In windows, the OS (HNS) chooses
	// the IP address space if the user does not specify an address space.
	UpdateIpamConfig(ipV4Data []IPAMData)
}

// Registerer provides a way for network drivers to be dynamically registered.
type Registerer interface {
	RegisterDriver(name string, driver Driver, capability Capability) error
}

// Capability represents the high level capabilities of the drivers which libnetwork can make use of
type Capability struct {
	DataScope         string
	ConnectivityScope string
}

// IPAMData represents the per-network ip related
// operational information libnetwork will send
// to the network driver during CreateNetwork()
type IPAMData struct {
	AddressSpace string
	Pool         *net.IPNet
	Gateway      *net.IPNet
	AuxAddresses map[string]*net.IPNet
}

// EventType defines a type for the CRUD event
type EventType uint8

const (
	// Create event is generated when a table entry is created,
	Create EventType = 1 + iota
	// Update event is generated when a table entry is updated.
	Update
	// Delete event is generated when a table entry is deleted.
	Delete
)

// ObjectType represents the type of object driver wants to store in libnetwork's networkDB
type ObjectType int

const (
	// EndpointObject should be set for libnetwork endpoint object related data
	EndpointObject ObjectType = 1 + iota
	// NetworkObject should be set for libnetwork network object related data
	NetworkObject
	// OpaqueObject is for driver specific data with no corresponding libnetwork object
	OpaqueObject
)

// IsValidType validates the passed in type against the valid object types
func IsValidType(objType ObjectType) bool {
	switch objType {
	case EndpointObject:
		fallthrough
	case NetworkObject:
		fallthrough
	case OpaqueObject:
		return true
	}
	return false
}
