package network

import "github.com/docker/docker/libnetwork"

type LibnetAdapter struct {
	controller *libnetwork.Controller
}

func NewLibnetAdapter(controller *libnetwork.Controller) LibnetAdapter {
	return LibnetAdapter{controller}
}

func (adapter LibnetAdapter)