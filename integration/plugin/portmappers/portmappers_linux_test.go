package portmappers

import (
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/docker/go-connections/nat"
	containertypes "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/v2/integration/internal/container"
	"github.com/moby/moby/v2/testutil/daemon"
	"gotest.tools/v3/assert"
)

func TestCustomPortMapper(t *testing.T) {
	plugin := newStubPluginServer(t, "test-mapper", map[string][]byte{})
	defer plugin.Close()

	ctx := setupTest(t)

	d := daemon.New(t)
	d.StartWithBusybox(ctx, t, "--default-port-mapper=test-mapper")
	defer d.Stop(t)
	c := d.NewClientT(t)
	defer c.Close()

	ctrId := container.Create(ctx, t, c,
		container.WithCmd("httpd", "-f"),
		container.WithExposedPorts("80/tcp"),
		container.WithPortMap(nat.PortMap{"80/tcp": {{}}}))
	defer c.ContainerRemove(ctx, ctrId, containertypes.RemoveOptions{Force: true})

	err := c.ContainerStart(ctx, ctrId, containertypes.StartOptions{})
	assert.ErrorContains(t, err, "Not implemented")
}

type stubPlugin struct {
	http      *http.Server
	httpCalls map[string][]byte
}

func newStubPluginServer(t *testing.T, pluginName string, stubResps map[string][]byte) stubPlugin {
	httpCalls := make(map[string][]byte)

	mux := http.NewServeMux()

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Implements": ["PortMapper"]}`))
	})

	mux.HandleFunc("/PortMapper.MapPorts", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		httpCalls["/PortMapper.MapPorts"] = body

		if stubResp, ok := stubResps["/PortMapper.MapPorts"]; ok {
			w.Write(stubResp)
		} else {
			w.Write([]byte(`{"Err": "Not implemented"}`))
		}
	})

	mux.HandleFunc("/PortMapper.UnmapPorts", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		httpCalls["/PortMapper.UnmapPorts"] = body

		if stubResp, ok := stubResps["/PortMapper.UnmapPorts"]; ok {
			w.Write(stubResp)
		} else {
			w.Write([]byte(`{"Err": "Not implemented"}`))
		}
	})

	l, err := net.Listen("unix", "/run/docker/plugins/"+pluginName+".sock")
	assert.NilError(t, err)

	plugin := stubPlugin{
		http: &http.Server{ //nolint:gosec // ignore G112: Potential Slowloris Attack. This is not a production server.
			Addr:    ":8080",
			Handler: mux,
		},
		httpCalls: httpCalls,
	}

	go plugin.http.Serve(l)

	return plugin
}

func (s stubPlugin) Close() {
	s.http.Close()
}
