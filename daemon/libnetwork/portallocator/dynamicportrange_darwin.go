//go:build !linux

package portallocator

import (
	"bytes"
	"fmt"
	"os/exec"
)

func getDynamicPortRange() (start, end int, _ error) {
	for sysctl, val := range map[string]*int{
		"net.inet.ip.portrange.hifirst": &start,
		"net.inet.ip.portrange.hilast":  &end,
	} {
		var buf bytes.Buffer
		cmd := exec.Command("/usr/sbin/sysctl", sysctl)
		cmd.Stdout = &buf
		if err := cmd.Run(); err != nil {
			return 0, 0, fmt.Errorf("port allocator - sysctl %s failed: %v", sysctl, err)
		}

		n, err := fmt.Sscanf(buf.String(), sysctl+": %d\n", val)
		if err != nil || n != 1 {
			return 0, 0, fmt.Errorf("failed to parse the output of sysctl %s: %v", sysctl, err)
		}
	}

	return start, end, nil
}

func getReservedPorts(_, _ int) (map[uint16]struct{}, error) {
	return nil, nil
}
