//go:build !windows

package libnetwork

import (
	"fmt"

	"github.com/docker/docker/libnetwork/driverapi"
)

// DriverInfo returns a collection of driver operational data related to this endpoint retrieved from the driver.
func (ep *Endpoint) DriverInfo() (map[string]interface{}, error) {
	ep, err := ep.retrieveFromStore()
	if err != nil {
		return nil, err
	}

	if sb, ok := ep.getSandbox(); ok {
		if gwep := sb.getEndpointInGWNetwork(); gwep != nil && gwep.ID() != ep.ID() {
			return gwep.DriverInfo()
		}
	}

	n, err := ep.getNetworkFromStore()
	if err != nil {
		return nil, fmt.Errorf("could not find network in store for driver info: %v", err)
	}

	driver, err := n.driver(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get driver info: %v", err)
	}

	epDrv, ok := driver.(driverapi.EndpointDriver)
	if !ok {
		return nil, nil
	}

	return epDrv.EndpointOperInfo(n.ID(), ep.ID())
}
