//go:build !linux

package portallocator

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func getDynamicPortRange() (start, end int, _ error) {
	for sysctl, val := range map[string]*int{
		"net.inet.ip.portrange.hifirst": &start,
		"net.inet.ip.portrange.hilast":  &end,
	} {
		v, err := unix.SysctlUint32(sysctl)
		if err != nil {
			return 0, 0, fmt.Errorf("port allocator - sysctl %s failed: %v", sysctl, err)
		}
		*val = int(v)
	}

	return start, end, nil
}
