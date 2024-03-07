package osl

import (
	"fmt"
	"net"

	"github.com/docker/docker/internal/sliceutil"
	"github.com/docker/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
)

// Gateway returns the IPv4 gateway for the sandbox.
func (n *Namespace) Gateway() net.IP {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.gw
}

// GatewayIPv6 returns the IPv6 gateway for the sandbox.
func (n *Namespace) GatewayIPv6() net.IP {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.gwv6
}

// StaticRoutes returns additional static routes for the sandbox. Note that
// directly connected routes are stored on the particular interface they
// refer to.
func (n *Namespace) StaticRoutes() []types.Route {
	n.mu.Lock()
	defer n.mu.Unlock()

	return sliceutil.Map(n.routes, func(r types.Route) types.Route {
		return types.Route{
			Destination: r.Destination,
			NextHop:     r.NextHop,
		}
	})
}

// SetGateway sets the default IPv4 gateway for the sandbox. It is a no-op
// if the given gateway is empty.
func (n *Namespace) SetGateway(gw net.IP) error {
	if len(gw) == 0 {
		return nil
	}

	if err := n.programGateway(gw, true); err != nil {
		return err
	}
	n.mu.Lock()
	n.gw = gw
	n.mu.Unlock()
	return nil
}

// UnsetGateway the previously set default IPv4 gateway in the sandbox.
// It is a no-op if no gateway was set.
func (n *Namespace) UnsetGateway() error {
	gw := n.Gateway()
	if len(gw) == 0 {
		return nil
	}

	if err := n.programGateway(gw, false); err != nil {
		return err
	}
	n.mu.Lock()
	n.gw = net.IP{}
	n.mu.Unlock()
	return nil
}

func (n *Namespace) programGateway(gw net.IP, isAdd bool) error {
	gwRoutes, err := n.nlHandle.RouteGet(gw)
	if err != nil {
		return fmt.Errorf("route for the gateway %s could not be found: %v", gw, err)
	}

	var linkIndex int
	for _, gwRoute := range gwRoutes {
		if gwRoute.Gw == nil {
			linkIndex = gwRoute.LinkIndex
			break
		}
	}

	if linkIndex == 0 {
		return fmt.Errorf("direct route for the gateway %s could not be found", gw)
	}

	if isAdd {
		return n.nlHandle.RouteAdd(&netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			LinkIndex: linkIndex,
			Gw:        gw,
		})
	}

	return n.nlHandle.RouteDel(&netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: linkIndex,
		Gw:        gw,
	})
}

// Program a route in to the namespace routing table.
func (n *Namespace) programRoute(dest *net.IPNet, nh net.IP) error {
	gwRoutes, err := n.nlHandle.RouteGet(nh)
	if err != nil {
		return fmt.Errorf("route for the next hop %s could not be found: %v", nh, err)
	}

	return n.nlHandle.RouteAdd(&netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: gwRoutes[0].LinkIndex,
		Gw:        nh,
		Dst:       dest,
	})
}

// Delete a route from the namespace routing table.
func (n *Namespace) removeRoute(dest *net.IPNet, nh net.IP) error {
	gwRoutes, err := n.nlHandle.RouteGet(nh)
	if err != nil {
		return fmt.Errorf("route for the next hop could not be found: %v", err)
	}

	return n.nlHandle.RouteDel(&netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: gwRoutes[0].LinkIndex,
		Gw:        nh,
		Dst:       dest,
	})
}

// SetGatewayIPv6 sets the default IPv6 gateway for the sandbox. It is a no-op
// if the given gateway is empty.
func (n *Namespace) SetGatewayIPv6(gwv6 net.IP) error {
	if len(gwv6) == 0 {
		return nil
	}

	if err := n.programGateway(gwv6, true); err != nil {
		return err
	}

	n.mu.Lock()
	n.gwv6 = gwv6
	n.mu.Unlock()
	return nil
}

// UnsetGatewayIPv6 unsets the previously set default IPv6 gateway in the sandbox.
// It is a no-op if no gateway was set.
func (n *Namespace) UnsetGatewayIPv6() error {
	gwv6 := n.GatewayIPv6()
	if len(gwv6) == 0 {
		return nil
	}

	if err := n.programGateway(gwv6, false); err != nil {
		return err
	}

	n.mu.Lock()
	n.gwv6 = net.IP{}
	n.mu.Unlock()
	return nil
}

// AddStaticRoute adds a static route to the sandbox.
func (n *Namespace) AddStaticRoute(r types.Route) error {
	if err := n.programRoute(r.Destination, r.NextHop); err != nil {
		return err
	}

	n.mu.Lock()
	n.routes = append(n.routes, r)
	n.mu.Unlock()
	return nil
}

// RemoveStaticRoute removes a static route from the sandbox.
func (n *Namespace) RemoveStaticRoute(r types.Route) error {
	if err := n.removeRoute(r.Destination, r.NextHop); err != nil {
		return err
	}

	n.mu.Lock()
	lastIndex := len(n.routes) - 1
	for i, v := range n.routes {
		if v.Destination == r.Destination && v.NextHop.Equal(r.NextHop) {
			// Overwrite the route we're removing with the last element
			n.routes[i] = n.routes[lastIndex]
			// Shorten the slice to trim the extra element
			n.routes = n.routes[:lastIndex]
			break
		}
	}
	n.mu.Unlock()
	return nil
}
