//go:build linux

package ipvlan

import (
	"context"
	"fmt"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/driverapi"
	"github.com/docker/docker/libnetwork/netlabel"
	"github.com/docker/docker/libnetwork/ns"
	"github.com/docker/docker/libnetwork/types"
)

// CreateEndpoint assigns the mac, ip and endpoint id for the new container
func (d *driver) CreateEndpoint(nid, eid string, opts driverapi.EndpointOptions) (driverapi.EndpointOptions, error) {
	if err := validateID(nid, eid); err != nil {
		return opts, err
	}
	n, err := d.getNetwork(nid)
	if err != nil {
		return opts, fmt.Errorf("network id %q not found", nid)
	}
	if opts.MACAddress != nil {
		return opts, fmt.Errorf("ipvlan interfaces do not support custom mac address assignment")
	}
	ep := &endpoint{
		id:     eid,
		nid:    nid,
		addr:   opts.Addr,
		addrv6: opts.AddrV6,
	}
	if ep.addr == nil {
		return opts, fmt.Errorf("create endpoint was not passed an IP address")
	}
	// disallow port mapping -p
	if opt, ok := opts.DriverOpts[netlabel.PortMap]; ok {
		if _, ok := opt.([]types.PortBinding); ok {
			if len(opt.([]types.PortBinding)) > 0 {
				log.G(context.TODO()).Warnf("ipvlan driver does not support port mappings")
			}
		}
	}
	// disallow port exposure --expose
	if opt, ok := opts.DriverOpts[netlabel.ExposedPorts]; ok {
		if _, ok := opt.([]types.TransportPort); ok {
			if len(opt.([]types.TransportPort)) > 0 {
				log.G(context.TODO()).Warnf("ipvlan driver does not support port exposures")
			}
		}
	}

	if err := d.storeUpdate(ep); err != nil {
		return opts, fmt.Errorf("failed to save ipvlan endpoint %.7s to store: %v", ep.id, err)
	}

	n.addEndpoint(ep)

	return opts, nil
}

// DeleteEndpoint remove the endpoint and associated netlink interface
func (d *driver) DeleteEndpoint(nid, eid string) error {
	if err := validateID(nid, eid); err != nil {
		return err
	}
	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %q not found", nid)
	}
	ep := n.endpoint(eid)
	if ep == nil {
		return fmt.Errorf("endpoint id %q not found", eid)
	}
	if link, err := ns.NlHandle().LinkByName(ep.srcName); err == nil {
		if err := ns.NlHandle().LinkDel(link); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("Failed to delete interface (%s)'s link on endpoint (%s) delete", ep.srcName, ep.id)
		}
	}

	if err := d.storeDelete(ep); err != nil {
		log.G(context.TODO()).Warnf("Failed to remove ipvlan endpoint %.7s from store: %v", ep.id, err)
	}
	n.deleteEndpoint(ep.id)
	return nil
}
