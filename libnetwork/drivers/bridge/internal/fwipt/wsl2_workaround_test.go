package fwipt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/docker/internal/testutils/netnsutils"
	"github.com/docker/docker/libnetwork/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestMirroredWSL2Workaround(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		loopback0        bool
		enableWorkaround bool
		wslinfoPerm      os.FileMode // 0 for no-file
		expLoopback0Rule bool
	}{
		{
			desc: "No loopback0",
		},
		{
			desc:             "WSL2 mirrored",
			loopback0:        true,
			enableWorkaround: true,
			wslinfoPerm:      0o777,
			expLoopback0Rule: true,
		},
		{
			desc:             "loopback0 but wslinfo not executable",
			loopback0:        true,
			enableWorkaround: true,
			wslinfoPerm:      0o666,
		},
		{
			desc:             "loopback0 but no wslinfo",
			loopback0:        true,
			enableWorkaround: true,
		},
		{
			desc:        "loopback0 but no userland proxy",
			loopback0:   true,
			wslinfoPerm: 0o777,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			defer netnsutils.SetupTestOSContext(t)()

			if tc.loopback0 {
				loopback0 := &netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Name: "loopback0",
					},
				}
				err := netlink.LinkAdd(loopback0)
				assert.NilError(t, err)
			}

			if tc.wslinfoPerm != 0 {
				wslinfoPathOrig := wslinfoPath
				defer func() {
					wslinfoPath = wslinfoPathOrig
				}()
				tmpdir := t.TempDir()
				wslinfoPath = filepath.Join(tmpdir, "wslinfo")
				err := os.WriteFile(wslinfoPath, []byte("#!/bin/sh\necho dummy file\n"), tc.wslinfoPerm)
				assert.NilError(t, err)
			}

			assert.NilError(t, setupHashNetIpset(IpsetExtBridges4, unix.AF_INET))

			config := Config{
				EnableV4:             true,
				EnableWSL2Workaround: tc.enableWorkaround,
			}
			_, _, _, _, err := setupIPChains(config, iptables.IPv4)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(mirroredWSL2Rule().Exists(), tc.expLoopback0Rule))
		})
	}
}
