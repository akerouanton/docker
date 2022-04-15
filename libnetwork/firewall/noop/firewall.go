package noop

import "github.com/docker/docker/libnetwork/firewall"

type NoopFirewall struct {}

func New() firewall.Firewall {
	return NoopFirewall{}
}

func (fw NoopFirewall) SetupRootNS() error {
	return nil
}

func (fw NoopFirewall) AddResolverConnectivity(protocol firewall.Protocol, dnsPort, resolverIP, resolverPort string) error {
	return nil
}
