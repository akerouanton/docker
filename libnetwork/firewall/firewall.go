package firewall

type Protocol string

const (
	UDP Protocol = "udp"
	TCP Protocol = "tcp"
)

type Mode int

const (
	IPv4 Mode = iota
	IPv6
	DualStack
)

func ModeFromBools(v4, v6 bool) Mode {
	if v4 && v6 {
		return DualStack
	}
	if v4 {
		return IPv4
	}
	if v6 {
		return IPv6
	}

	panic("Neither IPv4 nor IPv6 is enabled. This should not happen.")
}

type Firewall interface {
	// SetupRootNS is called when the firewall controller is created. It's used to create any required netfilter chain
	// (or anything like that). It can be called multiple times throughout firewall's lifecycle.
	SetupRootNS() error

	AddResolverConnectivity(protocol Protocol, dnsPort, resolverIP, resolverPort string) error

	AddInterNetworkConnectivity(mode Mode, iface string) error
	RemoveInterNetworkConnectivity(mode Mode, iface string) error

	AllowICC(mode Mode, iface string) error
	DenyICC(mode Mode, iface string) error
	CleanupICC(mode Mode, iface string) error
}

// NATRule is made of a protocol (eg. tcp or udp), a source ip and/or a source port, and a dest ip and/or a dest port.
type NATRule struct {
	Protocol Protocol
	SourceIP string
	SourcePort string
	DestIP string
	DestPort string
}
