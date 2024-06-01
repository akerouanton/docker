package portallocatorv2

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"syscall"

	"github.com/containerd/log"
)

type PortAllocator struct {
	EphemeralRange PortRange
	mu             sync.Mutex
}

type PortRange struct {
	Start, End uint16
}

type sockets []int

func (s sockets) Close() {
	for _, fd := range s {
		// Ignore uninitialized FDs. This can happen if Close() is open before
		// the underlying 'sockets' slice is completely filled.
		if fd == 0 {
			continue
		}
		if err := syscall.Close(fd); err != nil {
			log.G(context.TODO()).Errorf("failed to clean-up fd %d", fd)
		}
	}
}

func NewAllocator(ephemeral PortRange) *PortAllocator {
	return &PortAllocator{EphemeralRange: ephemeral}
}

func (pa *PortAllocator) requestPort(ip netip.Addr, proto string, port uint16, v6only bool) (_ int, retErr error) {
	family := syscall.AF_INET
	if ip.Is6() {
		family = syscall.AF_INET6
	}

	var sockType, sockProto int
	switch proto {
	case "tcp":
		sockType = syscall.SOCK_STREAM
		sockProto = syscall.IPPROTO_TCP
	case "udp":
		sockType = syscall.SOCK_DGRAM
		sockProto = syscall.IPPROTO_UDP
	case "sctp":
		sockType = syscall.SOCK_SEQPACKET
		sockType = syscall.IPPROTO_SCTP
	default:
		return -1, fmt.Errorf("PortAllocator: RequestPort: unsupported proto %q", proto)
	}

	fd, err := syscall.Socket(family, sockType|syscall.SOCK_CLOEXEC, sockProto)
	if err != nil {
		return -1, fmt.Errorf("socket syscall: %w", err)
	}
	defer func() {
		if retErr != nil {
			if err := syscall.Close(fd); err != nil {
				log.G(context.TODO()).Errorf("PortAllocator: RequestPort: failed to clean-up fd %d", fd)
			}
		}
	}()

	if family == syscall.AF_INET6 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, boolToInt(v6only)); err != nil {
			return -1, fmt.Errorf("setsockopt IPV6_V6ONLY: %w", err)
		}
	}

	if err := syscall.Bind(fd, sa); err != nil {
		return -1, fmt.Errorf("bind: %w", err)
	}

	return fd, nil
}

func boolToInt(v bool) int {
	if v == true {
		return 1
	}
	return 0
}

func (pa *PortAllocator) RequestPort(ips []netip.Addr, proto string, port uint16, v6only bool) (_ []int, retErr error) {
	fds := make(sockets, len(ips))
	defer func() {
		if retErr != nil {
			fds.Close()
		}
	}()

	for i, ip := range ips {
		var err error
		fds[i], err = pa.requestPort(ip, proto, port, v6only)
		if err != nil {

		}
	}
}

func (pa *PortAllocator) RequestRange(ips []netip.Addr, proto string, portStart, portEnd uint16, v6only bool) (_ []int, retErr error) {
	fds := make(sockets, 0, portEnd-portStart+1)
	defer func() {
		if retErr != nil {
			fds.Close()
		}
	}()

	for port := portStart; port <= portEnd; port++ {
		fd, err := pa.RequestPort(ip, proto, port, v6only)
		if err != nil {
			return nil, err
		}
		fds = append(fds, fd)
	}

	return fds, nil
}
