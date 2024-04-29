package defaultipam

import (
	"net/netip"
	"testing"
	"time"

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

func TestShufflerPickAll(t *testing.T) {
	s := newShuffler(6, 1)

	for _, want := range []uint64{2, 1, 4, 5, 3, 0} {
		v, ok := s.pickRandom()
		assert.Equal(t, v, want)
		assert.Equal(t, ok, true)
	}

	_, ok := s.pickRandom()
	assert.Equal(t, ok, false)
}

func TestShufflerGiveBack(t *testing.T) {
	s := newShuffler(10, 3)
	picked := make([]uint64, 0, 11)

	for i := 1; i <= 6; i++ {
		v, ok := s.pickRandom()
		assert.Equal(t, ok, true)
		picked = append(picked, v)
	}
	assert.DeepEqual(t, picked, []uint64{1, 4, 5, 0, 9, 3})

	s.giveBack(9)

	for i := 1; i <= 5; i++ {
		v, ok := s.pickRandom()
		assert.Equal(t, ok, true)
		picked = append(picked, v)
	}
	assert.DeepEqual(t, picked, []uint64{1, 4, 5, 0, 9, 3, 2, 6, 9, 7, 8})

	_, ok := s.pickRandom()
	assert.Equal(t, ok, false)
}

func BenchmarkShuffler(b *testing.B) {
	b.StopTimer()
	s := newShuffler(10000, time.Now().UTC().UnixNano())

	b.StartTimer()
	for i := 0; i < 10000; i++ {
		_, ok := s.pickRandom()
		if !ok {
			b.Fatal("pickRandom should not have reached the end yet")
		}
	}
}
