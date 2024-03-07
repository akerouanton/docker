package bridge

import (
	"testing"

	"github.com/docker/docker/internal/testutils/netnsutils"
	"github.com/docker/docker/libnetwork/driverapi"
	"github.com/docker/docker/libnetwork/netlabel"
	"github.com/vishvananda/netlink"
)

func TestLinkCreate(t *testing.T) {
	defer netnsutils.SetupTestOSContext(t)()
	d := newDriver()

	if err := d.configure(nil); err != nil {
		t.Fatalf("Failed to setup driver config: %v", err)
	}

	mtu := 1490
	config := &networkConfiguration{
		BridgeName: DefaultBridgeName,
		Mtu:        mtu,
		EnableIPv6: true,
	}
	genericOption := make(map[string]interface{})
	genericOption[netlabel.GenericData] = config

	ipdList := getIPv4Data(t)
	err := d.CreateNetwork("dummy", genericOption, nil, ipdList, getIPv6Data(t))
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	te := newTestEndpoint(ipdList[0].Pool, 10)
	_, err = d.CreateEndpoint("dummy", "", te.EndpointOptions())
	if err != nil {
		if _, ok := err.(InvalidEndpointIDError); !ok {
			t.Fatalf("Failed with an unexpected error: %s", err.Error())
		}
	} else {
		t.Fatal("Driver should have failed due to the empty eid")
	}

	// Good endpoint creation
	opts, err := d.CreateEndpoint("dummy", "ep", te.EndpointOptions())
	if err != nil {
		t.Fatalf("Failed to create a link: %s", err.Error())
	}

	epIface, err := d.Join("dummy", "ep", "sbox", te.JoinOptions(nil))
	if err != nil {
		t.Fatalf("Failed to create a link: %s", err.Error())
	}

	// Verify sbox endpoint interface inherited MTU value from bridge config
	sboxLnk, err := netlink.LinkByName(epIface.SrcName)
	if err != nil {
		t.Fatal(err)
	}
	if mtu != sboxLnk.Attrs().MTU {
		t.Fatal("Sandbox endpoint interface did not inherit bridge interface MTU config")
	}
	// TODO: if we could get peer name from (sboxLnk.(*netlink.Veth)).PeerName
	// then we could check the MTU on hostLnk as well.

	te1 := newTestEndpoint(ipdList[0].Pool, 11)
	_, err = d.CreateEndpoint("dummy", "ep", te1.EndpointOptions())
	if err == nil {
		t.Fatal("Failed to detect duplicate endpoint id on same network")
	}

	if epIface.DstPrefix == "" {
		t.Fatal("Invalid Dstname returned")
	}

	_, err = netlink.LinkByName(epIface.SrcName)
	if err != nil {
		t.Fatalf("Could not find source link %s: %v", epIface.SrcName, err)
	}

	n, ok := d.networks["dummy"]
	if !ok {
		t.Fatalf("Cannot find network %s inside driver", "dummy")
	}
	if !n.bridge.bridgeIPv4.Contains(epIface.Addr.IP) {
		t.Fatalf("IP %s is not a valid ip in the subnet %s", epIface.Addr.IP.String(), n.bridge.bridgeIPv4.String())
	}

	ip6 := opts.AddrV6.IP
	if !n.bridge.bridgeIPv6.Contains(ip6) {
		t.Fatalf("IP %s is not a valid ip in the subnet %s", ip6.String(), bridgeIPv6.String())
	}

	if !epIface.Gateway.Equal(n.bridge.bridgeIPv4.IP) {
		t.Fatalf("Invalid default gateway. Expected %s. Got %s", n.bridge.bridgeIPv4.IP.String(),
			epIface.Gateway.String())
	}

	if !epIface.GatewayV6.Equal(n.bridge.bridgeIPv6.IP) {
		t.Fatalf("Invalid default gateway for IPv6. Expected %s. Got %s", n.bridge.bridgeIPv6.IP.String(),
			epIface.GatewayV6.String())
	}
}

func TestLinkCreateTwo(t *testing.T) {
	defer netnsutils.SetupTestOSContext(t)()
	d := newDriver()

	if err := d.configure(nil); err != nil {
		t.Fatalf("Failed to setup driver config: %v", err)
	}

	config := &networkConfiguration{
		BridgeName: DefaultBridgeName,
		EnableIPv6: true,
	}
	genericOption := make(map[string]interface{})
	genericOption[netlabel.GenericData] = config

	ipdList := getIPv4Data(t)
	err := d.CreateNetwork("dummy", genericOption, nil, ipdList, getIPv6Data(t))
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	te1 := newTestEndpoint(ipdList[0].Pool, 11)
	_, err = d.CreateEndpoint("dummy", "ep", te1.EndpointOptions())
	if err != nil {
		t.Fatalf("Failed to create a link: %s", err.Error())
	}

	te2 := newTestEndpoint(ipdList[0].Pool, 12)
	_, err = d.CreateEndpoint("dummy", "ep", te2.EndpointOptions())
	if err != nil {
		if _, ok := err.(driverapi.ErrEndpointExists); !ok {
			t.Fatalf("Failed with a wrong error: %s", err.Error())
		}
	} else {
		t.Fatal("Expected to fail while trying to add same endpoint twice")
	}
}

func TestLinkCreateNoEnableIPv6(t *testing.T) {
	defer netnsutils.SetupTestOSContext(t)()
	d := newDriver()

	if err := d.configure(nil); err != nil {
		t.Fatalf("Failed to setup driver config: %v", err)
	}

	config := &networkConfiguration{
		BridgeName: DefaultBridgeName,
	}
	genericOption := make(map[string]interface{})
	genericOption[netlabel.GenericData] = config

	ipdList := getIPv4Data(t)
	err := d.CreateNetwork("dummy", genericOption, nil, ipdList, getIPv6Data(t))
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	te := newTestEndpoint(ipdList[0].Pool, 30)
	_, err = d.CreateEndpoint("dummy", "ep", te.EndpointOptions())
	if err != nil {
		t.Fatalf("Failed to create a link: %s", err.Error())
	}

	iface := te.iface
	if iface.addrv6 != nil && iface.addrv6.IP.To16() != nil {
		t.Fatalf("Expected IPv6 address to be nil when IPv6 is not enabled. Got IPv6 = %s", iface.addrv6.String())
	}

	if te.gw6.To16() != nil {
		t.Fatalf("Expected GatewayIPv6 to be nil when IPv6 is not enabled. Got GatewayIPv6 = %s", te.gw6.String())
	}
}

func TestLinkDelete(t *testing.T) {
	defer netnsutils.SetupTestOSContext(t)()
	d := newDriver()

	if err := d.configure(nil); err != nil {
		t.Fatalf("Failed to setup driver config: %v", err)
	}

	config := &networkConfiguration{
		BridgeName: DefaultBridgeName,
		EnableIPv6: true,
	}
	genericOption := make(map[string]interface{})
	genericOption[netlabel.GenericData] = config

	ipdList := getIPv4Data(t)
	err := d.CreateNetwork("dummy", genericOption, nil, ipdList, getIPv6Data(t))
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	te := newTestEndpoint(ipdList[0].Pool, 30)
	_, err = d.CreateEndpoint("dummy", "ep1", te.EndpointOptions())
	if err != nil {
		t.Fatalf("Failed to create a link: %s", err.Error())
	}

	err = d.DeleteEndpoint("dummy", "")
	if err != nil {
		if _, ok := err.(InvalidEndpointIDError); !ok {
			t.Fatalf("Failed with a wrong error :%s", err.Error())
		}
	} else {
		t.Fatal("Failed to detect invalid config")
	}

	err = d.DeleteEndpoint("dummy", "ep1")
	if err != nil {
		t.Fatal(err)
	}
}
