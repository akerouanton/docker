package remote

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/docker/docker/libnetwork/discoverapi"
	"github.com/docker/docker/libnetwork/driverapi"
	"github.com/docker/docker/libnetwork/scope"
	"github.com/docker/docker/libnetwork/types"
	"github.com/docker/docker/pkg/plugins"
)

func decodeToMap(r *http.Request) (res map[string]interface{}, err error) {
	err = json.NewDecoder(r.Body).Decode(&res)
	return
}

func handle(t *testing.T, mux *http.ServeMux, method string, h func(map[string]interface{}) interface{}) {
	mux.HandleFunc(fmt.Sprintf("/%s.%s", driverapi.NetworkPluginEndpointType, method), func(w http.ResponseWriter, r *http.Request) {
		ask, err := decodeToMap(r)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		answer := h(ask)
		err = json.NewEncoder(w).Encode(&answer)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func setupPlugin(t *testing.T, name string, mux *http.ServeMux) func() {
	specPath := "/etc/docker/plugins"
	if runtime.GOOS == "windows" {
		specPath = filepath.Join(os.Getenv("programdata"), "docker", "plugins")
	}

	if err := os.MkdirAll(specPath, 0o755); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if t.Failed() {
			_ = os.RemoveAll(specPath)
		}
	}()

	server := httptest.NewServer(mux)
	if server == nil {
		t.Fatal("Failed to start an HTTP Server")
	}

	if err := os.WriteFile(filepath.Join(specPath, name+".spec"), []byte(server.URL), 0o644); err != nil {
		t.Fatal(err)
	}

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", plugins.VersionMimetype)
		fmt.Fprintf(w, `{"Implements": ["%s"]}`, driverapi.NetworkPluginEndpointType)
	})

	return func() {
		if err := os.RemoveAll(specPath); err != nil {
			t.Fatal(err)
		}
		server.Close()
	}
}

type testEndpoint struct {
	t                     *testing.T
	src                   string
	dst                   string
	address               string
	addressIPv6           string
	macAddress            string
	gateway               string
	gatewayIPv6           string
	resolvConfPath        string
	hostsPath             string
	nextHop               string
	destination           string
	routeType             int
	disableGatewayService bool
}

func (test *testEndpoint) EndpointOptions() driverapi.EndpointOptions {
	return driverapi.EndpointOptions{
		MACAddress: test.MacAddress(),
		Addr:       test.Address(),
		AddrV6:     test.AddressIPv6(),
	}
}

func (te *testEndpoint) JoinOptions(driverOpts map[string]interface{}) driverapi.JoinOptions {
	return driverapi.JoinOptions{
		EndpointOptions: te.EndpointOptions(),
		DriverOpts:      driverOpts,
	}
}

func (test *testEndpoint) Address() *net.IPNet {
	if test.address == "" {
		return nil
	}
	nw, _ := types.ParseCIDR(test.address)
	return nw
}

func (test *testEndpoint) AddressIPv6() *net.IPNet {
	if test.addressIPv6 == "" {
		return nil
	}
	nw, _ := types.ParseCIDR(test.addressIPv6)
	return nw
}

func (test *testEndpoint) MacAddress() net.HardwareAddr {
	if test.macAddress == "" {
		return nil
	}
	mac, _ := net.ParseMAC(test.macAddress)
	return mac
}

func TestGetEmptyCapabilities(t *testing.T) {
	plugin := "test-net-driver-empty-cap"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	handle(t, mux, "GetCapabilities", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{}
	})

	p, err := plugins.Get(plugin, driverapi.NetworkPluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	client, err := getPluginClient(p)
	if err != nil {
		t.Fatal(err)
	}
	d := newDriver(plugin, client)
	if d.Type() != plugin {
		t.Fatal("Driver type does not match that given")
	}

	_, err = d.getCapabilities()
	if err == nil {
		t.Fatal("There should be error reported when get empty capability")
	}
}

func TestGetExtraCapabilities(t *testing.T) {
	plugin := "test-net-driver-extra-cap"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	handle(t, mux, "GetCapabilities", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"Scope":             "local",
			"foo":               "bar",
			"ConnectivityScope": "global",
		}
	})

	p, err := plugins.Get(plugin, driverapi.NetworkPluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	client, err := getPluginClient(p)
	if err != nil {
		t.Fatal(err)
	}
	d := newDriver(plugin, client)
	if d.Type() != plugin {
		t.Fatal("Driver type does not match that given")
	}

	c, err := d.getCapabilities()
	if err != nil {
		t.Fatal(err)
	} else if c.DataScope != scope.Local {
		t.Fatalf("get capability '%s', expecting 'local'", c.DataScope)
	} else if c.ConnectivityScope != scope.Global {
		t.Fatalf("get capability '%s', expecting %q", c.ConnectivityScope, scope.Global)
	}
}

func TestGetInvalidCapabilities(t *testing.T) {
	plugin := "test-net-driver-invalid-cap"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	handle(t, mux, "GetCapabilities", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"Scope": "fake",
		}
	})

	p, err := plugins.Get(plugin, driverapi.NetworkPluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	client, err := getPluginClient(p)
	if err != nil {
		t.Fatal(err)
	}
	d := newDriver(plugin, client)
	if d.Type() != plugin {
		t.Fatal("Driver type does not match that given")
	}

	_, err = d.getCapabilities()
	if err == nil {
		t.Fatal("There should be error reported when get invalid capability")
	}
}

func TestRemoteDriver(t *testing.T) {
	plugin := "test-net-driver"

	ep := &testEndpoint{
		t:              t,
		src:            "vethsrc",
		dst:            "vethdst",
		address:        "192.168.5.7/16",
		addressIPv6:    "2001:DB8::5:7/48",
		macAddress:     "ab:cd:ef:ee:ee:ee",
		gateway:        "192.168.0.1",
		gatewayIPv6:    "2001:DB8::1",
		hostsPath:      "/here/comes/the/host/path",
		resolvConfPath: "/there/goes/the/resolv/conf",
		destination:    "10.0.0.0/8",
		nextHop:        "10.0.0.1",
		routeType:      1,
	}

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	var networkID string

	handle(t, mux, "GetCapabilities", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"Scope": "global",
		}
	})
	handle(t, mux, "CreateNetwork", func(msg map[string]interface{}) interface{} {
		nid := msg["NetworkID"]
		var ok bool
		if networkID, ok = nid.(string); !ok {
			t.Fatal("RPC did not include network ID string")
		}
		return map[string]interface{}{}
	})
	handle(t, mux, "DeleteNetwork", func(msg map[string]interface{}) interface{} {
		if nid, ok := msg["NetworkID"]; !ok || nid != networkID {
			t.Fatal("Network ID missing or does not match that created")
		}
		return map[string]interface{}{}
	})
	handle(t, mux, "CreateEndpoint", func(msg map[string]interface{}) interface{} {
		iface := map[string]interface{}{
			"MacAddress":  ep.macAddress,
			"Address":     ep.address,
			"AddressIPv6": ep.addressIPv6,
		}
		return map[string]interface{}{
			"Interface": iface,
		}
	})
	handle(t, mux, "Join", func(msg map[string]interface{}) interface{} {
		options := msg["Options"].(map[string]interface{})
		foo, ok := options["foo"].(string)
		if !ok || foo != "fooValue" {
			t.Fatalf("Did not receive expected foo string in request options: %+v", msg)
		}
		return map[string]interface{}{
			"Gateway":        ep.gateway,
			"GatewayIPv6":    ep.gatewayIPv6,
			"HostsPath":      ep.hostsPath,
			"ResolvConfPath": ep.resolvConfPath,
			"InterfaceName": map[string]interface{}{
				"SrcName":   ep.src,
				"DstPrefix": ep.dst,
			},
			"StaticRoutes": []map[string]interface{}{
				{
					"Destination": ep.destination,
					"RouteType":   ep.routeType,
					"NextHop":     ep.nextHop,
				},
			},
		}
	})
	handle(t, mux, "Leave", func(msg map[string]interface{}) interface{} {
		return map[string]string{}
	})
	handle(t, mux, "DeleteEndpoint", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{}
	})
	handle(t, mux, "EndpointOperInfo", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"Value": map[string]string{
				"Arbitrary": "key",
				"Value":     "pairs?",
			},
		}
	})
	handle(t, mux, "DiscoverNew", func(msg map[string]interface{}) interface{} {
		return map[string]string{}
	})
	handle(t, mux, "DiscoverDelete", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{}
	})

	p, err := plugins.Get(plugin, driverapi.NetworkPluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	client, err := getPluginClient(p)
	if err != nil {
		t.Fatal(err)
	}
	d := newDriver(plugin, client)
	if d.Type() != plugin {
		t.Fatal("Driver type does not match that given")
	}

	c, err := d.getCapabilities()
	if err != nil {
		t.Fatal(err)
	} else if c.DataScope != scope.Global {
		t.Fatalf("get capability '%s', expecting 'global'", c.DataScope)
	}

	netID := "dummy-network"
	err = d.CreateNetwork(netID, map[string]interface{}{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	endID := "dummy-endpoint"
	opts, err := d.CreateEndpoint(netID, endID, driverapi.EndpointOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ep.MacAddress(), opts.MACAddress) || !types.CompareIPNet(ep.Address(), opts.Addr) ||
		!types.CompareIPNet(ep.AddressIPv6(), opts.AddrV6) {
		t.Fatalf("Unexpected InterfaceInfo data. Expected (%s, %s, %s). Got (%v, %v, %v)",
			ep.MacAddress(), ep.Address(), ep.AddressIPv6(),
			opts.MACAddress, opts.Addr, opts.AddrV6)
	}

	joinOpts := map[string]interface{}{"foo": "fooValue"}
	_, err = d.Join(netID, endID, "sandbox-key", ep.JoinOptions(joinOpts))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.EndpointOperInfo(netID, endID); err != nil {
		t.Fatal(err)
	}
	if err = d.Leave(netID, endID); err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteEndpoint(netID, endID); err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteNetwork(netID); err != nil {
		t.Fatal(err)
	}

	data := discoverapi.NodeDiscoveryData{
		Address: "192.168.1.1",
	}
	if err = d.DiscoverNew(discoverapi.NodeDiscovery, data); err != nil {
		t.Fatal(err)
	}
	if err = d.DiscoverDelete(discoverapi.NodeDiscovery, data); err != nil {
		t.Fatal(err)
	}
}

func TestDriverError(t *testing.T) {
	plugin := "test-net-driver-error"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	handle(t, mux, "CreateEndpoint", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"Err": "this should get raised as an error",
		}
	})

	p, err := plugins.Get(plugin, driverapi.NetworkPluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	client, err := getPluginClient(p)
	if err != nil {
		t.Fatal(err)
	}

	d := newDriver(plugin, client)
	if _, err := d.CreateEndpoint("dummy", "dummy", driverapi.EndpointOptions{}); err == nil {
		t.Fatal("Expected error from driver")
	}
}

func TestMissingValues(t *testing.T) {
	plugin := "test-net-driver-missing"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	ep := &testEndpoint{
		t: t,
	}

	handle(t, mux, "CreateEndpoint", func(msg map[string]interface{}) interface{} {
		iface := map[string]interface{}{
			"Address":     ep.address,
			"AddressIPv6": ep.addressIPv6,
			"MacAddress":  ep.macAddress,
		}
		return map[string]interface{}{
			"Interface": iface,
		}
	})

	p, err := plugins.Get(plugin, driverapi.NetworkPluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	client, err := getPluginClient(p)
	if err != nil {
		t.Fatal(err)
	}

	d := newDriver(plugin, client)
	if _, err := d.CreateEndpoint("dummy", "dummy", driverapi.EndpointOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestRollback(t *testing.T) {
	plugin := "test-net-driver-rollback"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	rolledback := false

	handle(t, mux, "CreateEndpoint", func(msg map[string]interface{}) interface{} {
		iface := map[string]interface{}{
			"Address":     "192.168.4.5/16",
			"AddressIPv6": "",
			"MacAddress":  "7a:12:34:56:78:90",
		}
		return map[string]interface{}{
			"Interface": interface{}(iface),
		}
	})
	handle(t, mux, "DeleteEndpoint", func(msg map[string]interface{}) interface{} {
		rolledback = true
		return map[string]interface{}{}
	})

	p, err := plugins.Get(plugin, driverapi.NetworkPluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	client, err := getPluginClient(p)
	if err != nil {
		t.Fatal(err)
	}

	d := newDriver(plugin, client)
	var epOpts driverapi.EndpointOptions
	epOpts.MACAddress, _ = net.ParseMAC("01:de:ad:be:ef:09")
	if _, err := d.CreateEndpoint("dummy", "dummy", epOpts); err == nil {
		// The remote driver should not accept a plugin which set the MAC
		// address whereas the input options already have one specified.
		t.Fatal("Expected error from driver")
	}
	if !rolledback {
		t.Fatal("Expected to have had DeleteEndpoint called")
	}
}
