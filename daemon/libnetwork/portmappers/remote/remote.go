package remote

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/containerd/log"
	"github.com/moby/moby/v2/daemon/internal/sliceutil"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
	"github.com/moby/moby/v2/pkg/plugingetter"
	"github.com/moby/moby/v2/pkg/plugins"
)

const (
	PluginType = "PortMapper"

	MapPortsEndpoint   = "/PortMapper.MapPorts"
	UmnapPortsEndpoint = "/PortMapper.UnmapPorts"
)

type portMapper struct {
	name   string
	client *plugins.Client
}

func Register(r portmapperapi.Registerer, pg plugingetter.PluginGetter) error {
	newPluginHandler := func(name string, client *plugins.Client) {
		if err := r.Register(name, newPortMapper(name, client)); err != nil {
			log.G(context.TODO()).WithError(err).Errorf("error registering remote port mapper %s", name)
		}
	}

	// Register currently active portmapper plugins.
	activePlugins := pg.GetAllManagedPluginsByCap(PluginType)
	for _, p := range activePlugins {
		client, err := makePluginClient(p)
		if err != nil {
			return err
		}
		newPluginHandler(p.Name(), client)
	}

	// Register the plugin handler called when a new portmapper plugin is enabled.
	pg.Handle(PluginType, newPluginHandler)

	return nil
}

func newPortMapper(name string, client *plugins.Client) portmapperapi.PortMapper {
	return &portMapper{name: name, client: client}
}

func makePluginClient(p plugingetter.CompatPlugin) (*plugins.Client, error) {
	if v1, ok := p.(plugingetter.PluginWithV1Client); ok {
		return v1.Client(), nil
	}

	pa, ok := p.(plugingetter.PluginAddr)
	if !ok {
		return nil, fmt.Errorf("unknown plugin type %T", p)
	}

	if pa.Protocol() != plugins.ProtocolSchemeHTTPV1 {
		return nil, fmt.Errorf("unsupported plugin protocol %s", pa.Protocol())
	}

	addr := pa.Addr()
	client, err := plugins.NewClientWithTimeout(addr.Network()+"://"+addr.String(), nil, pa.Timeout())
	if err != nil {
		return nil, fmt.Errorf("error creating plugin client: %w", err)
	}

	return client, nil
}

func (pm *portMapper) MapPorts(ctx context.Context, reqs []portmapperapi.PortBindingReq, labels map[string]string) ([]portmapperapi.PortBinding, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	req := MapPortsRequest{
		Reqs: sliceutil.Map(reqs, func(pbReq portmapperapi.PortBindingReq) PortBindingReq {
			backendIP, _ := netip.AddrFromSlice(pbReq.IP)
			frontendIPs, _ := netip.AddrFromSlice(pbReq.HostIP)

			return PortBindingReq{
				Proto:           pbReq.Proto,
				BackendIP:       backendIP.Unmap(),
				BackendPort:     pbReq.Port,
				FrontendIP:      frontendIPs.Unmap(),
				FrontendPort:    pbReq.HostPort,
				FrontendPortEnd: pbReq.HostPortEnd,
			}
		}),
		Labels: labels,
	}

	var resp MapPortsResponse
	if err := pm.client.CallWithOptions(MapPortsEndpoint, req, &resp); err != nil {
		return nil, fmt.Errorf("error calling %s on remote port mapper %s: %w", MapPortsEndpoint, pm.name, err)
	}

	if resp.Err != "" {
		return nil, errors.New(resp.Err)
	}

	var pbs []portmapperapi.PortBinding
	for _, pb := range resp.PortBindings {
		if pb.DiscardReq {
			if pb.Error != nil {
				log.G(ctx).Infof("port mapping discarded by plugin %s: %v", pm.name, pb.Error)
			}
			continue
		}

		pbs = append(pbs, portmapperapi.PortBinding{
			PortBinding: types.PortBinding{
				IP:          pb.BackendIP.AsSlice(),
				Port:        pb.BackendPort,
				Proto:       pb.Proto,
				HostIP:      pb.FrontendIP.AsSlice(),
				HostPort:    pb.FrontendPort,
				HostPortEnd: pb.FrontendPort,
			},
		})
	}

	log.G(ctx).Infof("remote port mapper %s mapped ports sccessfully: %+v", pm.name, pbs)

	return pbs, nil
}

func (pm *portMapper) UnmapPorts(ctx context.Context, pbs []portmapperapi.PortBinding, labels map[string]string) error {
	req := UnmapPortsRequest{
		PortBindings: sliceutil.Map(pbs, func(pb portmapperapi.PortBinding) PortBinding {
			backendIP, _ := netip.AddrFromSlice(pb.IP)
			frontendIP, _ := netip.AddrFromSlice(pb.HostIP)

			return PortBinding{
				Proto:        pb.Proto,
				BackendIP:    backendIP.Unmap(),
				BackendPort:  pb.Port,
				FrontendIP:   frontendIP.Unmap(),
				FrontendPort: pb.HostPort,
			}
		}),
		Labels: labels,
	}

	if err := pm.client.CallWithOptions(UmnapPortsEndpoint, req, nil); err != nil {
		return fmt.Errorf("error calling %s on remote port mapper %s: %w", UmnapPortsEndpoint, pm.name, err)
	}

	log.G(ctx).Infof("remote port mapper %s un-mapped ports sccessfully: %+v", pm.name, pbs)

	return nil
}
