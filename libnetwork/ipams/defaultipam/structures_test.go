package defaultipam

import (
	"net/netip"
	"testing"

	"gotest.tools/v3/assert"
)

func TestDoubleCursor(t *testing.T) {
	allocated := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/24"),
		netip.MustParsePrefix("172.17.0.0/24"),
		netip.MustParsePrefix("172.18.0.0/24"),
	}
	reserved := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/24"),
	}
	dc := newDoubleCursor(allocated, reserved, func(a, b netip.Prefix) bool {
		return a.Addr().Less(b.Addr())
	})

	for _, exp := range []netip.Prefix{
		allocated[0],
		reserved[0],
		allocated[1],
		allocated[2],
		{},
	} {
		assert.Equal(t, dc.Get(), exp)
		dc.Inc()
	}
}
