package network

import (
	"testing"

	types "github.com/docker/docker/api/types/network"
	"gotest.tools/v3/assert"
)

func TestNetworkWithInvalidIPAM(t *testing.T) {
	testcases := []struct {
		name           string
		ipam           types.IPAM
		ipv6           bool
		expectedErrors []string
	}{
		{
			name: "IP version mismatch",
			ipam: types.IPAM{
				Config: []types.IPAMConfig{{
					Subnet:     "10.10.10.0/24",
					IPRange:    "2001:db8::/32",
					Gateway:    "2001:db8::1",
					AuxAddress: map[string]string{"DefaultGatewayIPv4": "2001:db8::1"},
				}},
			},
			expectedErrors: []string{
				"ip-range 2001:db8::/32 is an IPv6 block whereas it's associated to an IPv4 subnet",
				"gateway 2001:db8::1 is an IPv6 address whereas it's associated to an IPv4 subnet",
				"auxiliary address DefaultGatewayIPv4 is an IPv6 address whereas it's associated to an IPv4 subnet",
			},
		},
		{
			name:           "IPv6 subnet is discarded when IPv6 is disabled",
			ipam:           types.IPAM{Config: []types.IPAMConfig{{Subnet: "2001:db8::/32"}}},
			ipv6:           false,
			expectedErrors: []string{"IPv6 has not been enabled for this network, but an IPv6 subnet has been provided"},
		},
		{
			name: "Invalid data - Subnet",
			ipam: types.IPAM{Config: []types.IPAMConfig{{Subnet: "foobar"}}},
			expectedErrors: []string{
				"subnet \"foobar\" is an invalid prefix",
			},
		},
		{
			name: "Invalid data",
			ipam: types.IPAM{
				Config: []types.IPAMConfig{{
					Subnet:     "10.10.10.0/24",
					IPRange:    "foobar",
					Gateway:    "barbaz",
					AuxAddress: map[string]string{"DefaultGatewayIPv4": "dummy"},
				}},
			},
			expectedErrors: []string{
				"ip-range \"foobar\" is an invalid prefix",
				"gateway \"barbaz\" is an invalid address",
				"auxiliary address \"dummy\" is an invalid address",
			},
		},
		{
			name: "IPRange bigger than its subnet",
			ipam: types.IPAM{
				Config: []types.IPAMConfig{
					{Subnet: "10.10.10.0/24", IPRange: "10.0.0.0/8"},
				},
			},
			expectedErrors: []string{
				"ip-range 10.0.0.0/8 is bigger than its associated subnet",
			},
		},
		{
			name: "Out of range prefix & addresses",
			ipam: types.IPAM{
				Config: []types.IPAMConfig{{
					Subnet:     "10.0.0.0/8",
					IPRange:    "192.168.0.1/24",
					Gateway:    "192.168.0.1",
					AuxAddress: map[string]string{"DefaultGatewayIPv4": "192.168.0.1"},
				}},
			},
			expectedErrors: []string{
				"subnet doesn't contain ip-range 192.168.0.1/24",
				"subnet doesn't contain gateway 192.168.0.1",
				"subnet doesn't contain auxiliary address 192.168.0.1",
			},
		},
		{
			name: "Subnet with host fragment set",
			ipam: types.IPAM{
				Config: []types.IPAMConfig{{
					Subnet: "10.10.10.0/8",
				}},
			},
			expectedErrors: []string{"subnet 10.10.10.0/8 has some bits set in its host fragment"},
		},
		{
			name: "IPRange with host fragment set",
			ipam: types.IPAM{
				Config: []types.IPAMConfig{{
					Subnet:  "10.0.0.0/8",
					IPRange: "10.10.10.0/16",
				}},
			},
			expectedErrors: []string{"ip-range 10.10.10.0/16 has some bits set in its host fragment"},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errs := validateIPAM(&tc.ipam, tc.ipv6)
			for _, err := range tc.expectedErrors {
				assert.ErrorContains(t, errs, err)
			}
		})
	}
}
