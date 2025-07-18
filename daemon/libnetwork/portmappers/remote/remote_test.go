package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/moby/moby/v2/daemon/internal/sliceutil"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
	"github.com/moby/moby/v2/pkg/plugins"
	"gotest.tools/v3/assert"
)

func TestMapUnmapPorts(t *testing.T) {
	testcases := []struct {
		name   string
		labels map[string]string
		pbReqs []portmapperapi.PortBindingReq

		mapHTTPStatus int  // HTTP status code returned by the stub plugin when MapPorts is called
		discardIPv6   bool // Instruct the stub plugin to discard IPv6 port bindings

		expMapReq MapPortsRequest             // Requests sent to the stub plugin by the remote portmapper to map ports
		expPBs    []portmapperapi.PortBinding // Port bindings returned by the remote portmapper after it called the stub plugin
		expMapErr string                      // Error returned by the remote portmapper after calling the stub plugin

		expUnmapReq UnmapPortsRequest // Requests sent to the stub plugin by the remote portmapper to unmap ports
	}{
		{
			name:   "valid request",
			labels: map[string]string{"foo": "bar"},
			pbReqs: []portmapperapi.PortBindingReq{
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("172.17.0.3"), Port: 80, HostIP: net.IPv4zero, HostPort: 80, HostPortEnd: 82}},
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("fd33:8c66:7f44::3"), Port: 80, HostIP: net.IPv6zero, HostPort: 80, HostPortEnd: 82}},
			},
			expMapReq: MapPortsRequest{
				Reqs: []PortBindingReq{
					{Proto: types.TCP, BackendIP: netip.MustParseAddr("172.17.0.3"), BackendPort: 80, FrontendIP: netip.IPv4Unspecified(), FrontendPort: 80, FrontendPortEnd: 82},
					{Proto: types.TCP, BackendIP: netip.MustParseAddr("fd33:8c66:7f44::3"), BackendPort: 80, FrontendIP: netip.IPv6Unspecified(), FrontendPort: 80, FrontendPortEnd: 82},
				},
				Labels: map[string]string{"foo": "bar"},
			},
			expPBs: []portmapperapi.PortBinding{
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("172.17.0.3"), Port: 80, HostIP: net.IPv4zero, HostPort: 80, HostPortEnd: 80}},
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("fd33:8c66:7f44::3"), Port: 80, HostIP: net.IPv6zero, HostPort: 80, HostPortEnd: 80}},
			},
			expUnmapReq: UnmapPortsRequest{
				PortBindings: []PortBinding{
					{Proto: types.TCP, BackendIP: netip.MustParseAddr("172.17.0.3"), BackendPort: 80, FrontendIP: netip.IPv4Unspecified(), FrontendPort: 80},
					{Proto: types.TCP, BackendIP: netip.MustParseAddr("fd33:8c66:7f44::3"), BackendPort: 80, FrontendIP: netip.IPv6Unspecified(), FrontendPort: 80},
				},
				Labels: map[string]string{"foo": "bar"},
			},
		},
		{
			name: "discard binding",
			pbReqs: []portmapperapi.PortBindingReq{
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("172.17.0.3"), Port: 80, HostIP: net.IPv4zero, HostPort: 80, HostPortEnd: 82}},
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("fd33:8c66:7f44::3"), Port: 80, HostIP: net.IPv6zero, HostPort: 80, HostPortEnd: 82}},
			},
			discardIPv6: true,
			expMapReq: MapPortsRequest{
				Reqs: []PortBindingReq{
					{Proto: types.TCP, BackendIP: netip.MustParseAddr("172.17.0.3"), BackendPort: 80, FrontendIP: netip.IPv4Unspecified(), FrontendPort: 80, FrontendPortEnd: 82},
					{Proto: types.TCP, BackendIP: netip.MustParseAddr("fd33:8c66:7f44::3"), BackendPort: 80, FrontendIP: netip.IPv6Unspecified(), FrontendPort: 80, FrontendPortEnd: 82},
				},
			},
			expPBs: []portmapperapi.PortBinding{
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("172.17.0.3"), Port: 80, HostIP: net.IPv4zero, HostPort: 80, HostPortEnd: 80}},
			},
			expUnmapReq: UnmapPortsRequest{
				PortBindings: []PortBinding{
					{Proto: types.TCP, BackendIP: netip.MustParseAddr("172.17.0.3"), BackendPort: 80, FrontendIP: netip.IPv4Unspecified(), FrontendPort: 80},
				},
			},
		},
		{
			name: "plugin fails to MapPorts",
			pbReqs: []portmapperapi.PortBindingReq{
				{PortBinding: types.PortBinding{Proto: types.TCP, IP: net.ParseIP("172.17.0.3"), Port: 80, HostIP: net.IPv4zero, HostPort: 80, HostPortEnd: 82}},
			},
			mapHTTPStatus: http.StatusBadRequest,
			expMapErr:     "error calling /PortMapper.MapPorts on remote port mapper test-mapper: /PortMapper.MapPorts: MapPorts failed",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Clean up existing plugin socket from previous test runs if needed.
			if err := os.Remove("/run/docker/plugins/test-mapper.sock"); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed to remove existing plugin socket: %v", err)
			}

			p := newStubPluginServer(t, "test-mapper", tc.mapHTTPStatus, tc.discardIPv6)
			defer p.http.Close()

			c, err := plugins.NewClient(p.http.Addr, nil)
			assert.NilError(t, err)
			pm := newPortMapper("test-mapper", c)

			pbs, err := pm.MapPorts(context.Background(), tc.pbReqs, tc.labels)
			assert.DeepEqual(t, tc.expMapReq, p.mapReq, cmpopts.EquateComparable(netip.Addr{}))
			assert.DeepEqual(t, tc.expPBs, pbs, cmpopts.EquateComparable(netip.AddrPort{}))
			if tc.expMapErr != "" {
				assert.ErrorContains(t, err, tc.expMapErr)
				return
			}

			err = pm.UnmapPorts(context.Background(), tc.expPBs, tc.labels)
			assert.DeepEqual(t, tc.expUnmapReq, p.unmapReq, cmpopts.EquateComparable(netip.Addr{}))
			assert.NilError(t, err)
		})
	}
}

type stubPlugin struct {
	http     *http.Server
	mapReq   MapPortsRequest
	unmapReq UnmapPortsRequest
}

func newStubPluginServer(t *testing.T, pluginName string, mapHTTPStatus int, discardIPv6 bool) *stubPlugin {
	l, err := net.Listen("unix", "/run/docker/plugins/"+pluginName+".sock")
	assert.NilError(t, err)
	t.Cleanup(func() {
		l.Close()
	})

	mux := http.NewServeMux()
	plugin := &stubPlugin{
		http: &http.Server{ //nolint:gosec // ignore G112: Potential Slowloris Attack. This is not a production server.
			Addr:    "unix://" + l.Addr().(*net.UnixAddr).Name,
			Handler: mux,
		},
	}

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Implements": ["PortMapper"]}`))
	})

	mux.HandleFunc("/PortMapper.MapPorts", func(w http.ResponseWriter, r *http.Request) {
		if mapHTTPStatus != 0 && mapHTTPStatus != http.StatusOK {
			http.Error(w, "MapPorts failed", mapHTTPStatus)
			return
		}

		var req MapPortsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		plugin.mapReq = req

		pbs := sliceutil.Map(req.Reqs, func(pbReq PortBindingReq) PortBinding {
			pb := PortBinding{
				Proto:        pbReq.Proto,
				BackendIP:    pbReq.BackendIP,
				BackendPort:  pbReq.BackendPort,
				FrontendIP:   pbReq.FrontendIP,
				FrontendPort: pbReq.FrontendPort,
			}
			if discardIPv6 && pbReq.FrontendIP.Is6() {
				pb.DiscardReq = true
			}
			return pb
		})
		if err := json.NewEncoder(w).Encode(MapPortsResponse{PortBindings: pbs}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/PortMapper.UnmapPorts", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&plugin.unmapReq); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	go plugin.http.Serve(l)

	return plugin
}
