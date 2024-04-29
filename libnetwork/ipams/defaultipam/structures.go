package defaultipam

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"

	"github.com/docker/docker/libnetwork/bitmap"
	"github.com/docker/docker/libnetwork/types"
)

// PoolID is the pointer to the configured pools in each address space
type PoolID struct {
	AddressSpace string
	SubnetKey
}

// PoolData contains the configured pool data
type PoolData struct {
	addrs    *bitmap.Bitmap
	children map[netip.Prefix]struct{}

	// Whether to implicitly release the pool once it no longer has any children.
	autoRelease bool
}

// SubnetKey is the composite key to an address pool within an address space.
type SubnetKey struct {
	Subnet, ChildSubnet netip.Prefix
}

func (k SubnetKey) Is6() bool {
	return k.Subnet.Addr().Is6()
}

// PoolIDFromString creates a new PoolID and populates the SubnetKey object
// reading it from the given string.
func PoolIDFromString(str string) (pID PoolID, err error) {
	if str == "" {
		return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
	}

	p := strings.Split(str, "/")
	if len(p) != 3 && len(p) != 5 {
		return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
	}
	pID.AddressSpace = p[0]
	pID.Subnet, err = netip.ParsePrefix(p[1] + "/" + p[2])
	if err != nil {
		return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
	}
	if len(p) == 5 {
		pID.ChildSubnet, err = netip.ParsePrefix(p[3] + "/" + p[4])
		if err != nil {
			return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
		}
	}

	return pID, nil
}

// String returns the string form of the SubnetKey object
func (s *PoolID) String() string {
	if s.ChildSubnet == (netip.Prefix{}) {
		return s.AddressSpace + "/" + s.Subnet.String()
	} else {
		return s.AddressSpace + "/" + s.Subnet.String() + "/" + s.ChildSubnet.String()
	}
}

// String returns the string form of the PoolData object
func (p *PoolData) String() string {
	return fmt.Sprintf("PoolData[Children: %d]", len(p.children))
}

// doubleCursor is used to iterate on both 'a' and 'b' at the same time while
// maintaining the total order that would arise if both were merged and then
// sorted. Both 'a' and 'b' have to be sorted beforehand.
type doubleCursor struct {
	a      []netip.Prefix
	b      []netip.Prefix
	ia, ib int
	cmp    func(a, b netip.Prefix) bool
	lastA  bool
}

func newDoubleCursor(a, b []netip.Prefix, cmp func(a, b netip.Prefix) bool) *doubleCursor {
	return &doubleCursor{
		a:   a,
		b:   b,
		cmp: cmp,
	}
}

func (dc *doubleCursor) Get() netip.Prefix {
	if dc.ia < len(dc.a) && dc.ib < len(dc.b) {
		if dc.cmp(dc.a[dc.ia], dc.b[dc.ib]) {
			dc.lastA = true
			return dc.a[dc.ia]
		}
		dc.lastA = false
		return dc.b[dc.ib]
	} else if dc.ia < len(dc.a) {
		dc.lastA = true
		return dc.a[dc.ia]
	} else if dc.ib < len(dc.b) {
		dc.lastA = false
		return dc.b[dc.ib]
	}

	return netip.Prefix{}
}

func (dc *doubleCursor) Inc() {
	if dc.lastA {
		dc.ia++
	} else {
		dc.ib++
	}
}

// shuffler is an implementation of the Fisher-Yates shuffle algorithm. It's
// used to generate only once, and with a uniform distribution, each number in
// the range [0, imax), where imax < 1<<63. It works by associating a position
// to each number, and swapping number at the generated position with the
// latest position reachable.
//
// In its initial state, no permutations are tracked and i = imax. When
// pickRandom is called:
//
//   - A new random number in the range [0, i) is generated.
//   - Since there's no permutation, the returned number is exactly the one
//     generated.
//   - A new permutation is inserted -- number at the 'generated' position now
//     equals to the number at position i-1.
//   - i is decremented.
//
// On subsequent run, when a generated number matches a permutation, the
// returned number is the permuted number.
//
// For instance, let's take the range [0, 5]. i is initialized at 6, no
// permutations are tracked yet:
//
//	i = 6
//	Position: [ 0 ] [ 1 ] [ 2 ] [ 3 ] [ 4 ] [ 5 ]
//	Value:    [ 0 ] [ 1 ] [ 2 ] [ 3 ] [ 4 ] [ 5 ]
//
// On first run, a new random number is generated -- let's say 3. There's no
// permutation, so that's the number returned. The number at position i (ie. 5)
// is swapped with position 3:
//
//	i = 5
//	Position: [ 0 ] [ 1 ] [ 2 ] [ 3 ] [ 4 ] / [ 5 ]
//	Value:    [ 0 ] [ 1 ] [ 2 ] [ 5 ] [ 4 ] / [   ]
//	Returned: 3
//
// On next run, a new random number is generated -- 3 again. That's a permuted
// number, so 5 is returned this time. Again, the number at position i is
// swapped with position 3 (i.e. 4 this time):
//
//	i = 4
//	Position: [ 0 ] [ 1 ] [ 2 ] [ 3 ] / [ 4 ] [ 5 ]
//	Value:    [ 0 ] [ 1 ] [ 2 ] [ 4 ] / [   ] [   ]
//	Returned: 5
//
// On next run, a new random number is generated -- this time: 1. There's no
// permutation, so 1 is returned. Again, the number at position i is swapped
// with position 1 (i.e. again: 4):
//
//	i = 3
//	Position: [ 0 ] [ 1 ] [ 2 ] / [ 3 ] [ 4 ] [ 5 ]
//	Value:    [ 0 ] [ 4 ] [ 2 ] / [   ] [   ] [   ]
//	Returned: 1
//
// Now, let's say we want to give back a number previously picked by
// [pickRandom] -- let's take 5 as an example. We need to increment i, and
// track a new permutation:
//
//	i = 4
//	Position: [ 0 ] [ 1 ] [ 2 ] [ 3 ] / [ 4 ] [ 5 ]
//	Value:    [ 0 ] [ 4 ] [ 2 ] [ 5 ] / [   ] [   ]
type shuffler struct {
	r       *rand.Rand
	permuts map[uint64]uint64
	i       int64
}

func newShuffler(imax int64, seed int64) *shuffler {
	return &shuffler{
		r:       rand.New(rand.NewSource(seed)),
		permuts: make(map[uint64]uint64),
		i:       imax,
	}
}

// pickRandom returns a random number.
func (s *shuffler) pickRandom() (uint64, bool) {
	if s.i == 0 {
		return 0, false
	}

	// Int63n generates a random number in the half-open interval [0, s.i).
	pos := uint64(s.r.Int63n(s.i))

	s.i--
	val := s.atPos(pos)
	s.permuts[pos] = s.atPos(uint64(s.i))
	delete(s.permuts, uint64(s.i+1))

	return val, true
}

// atPos returns the number at position 'pos'. If no permutation is found for
// this position, the number associated with this position is the position
// number.
func (s *shuffler) atPos(pos uint64) uint64 {
	if perm, ok := s.permuts[pos]; ok {
		return perm
	}
	return pos
}

// giveBack puts back a given value into the set of values that can be
// generated by the shuffler.
func (s *shuffler) giveBack(v uint64) {
	s.permuts[uint64(s.i)] = v
	s.i++
}
