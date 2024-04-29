package defaultipam

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/internal/netiputil"
	"github.com/docker/docker/libnetwork/ipamapi"
	"github.com/docker/docker/libnetwork/ipamutils"
	"github.com/docker/docker/libnetwork/ipbits"
	"github.com/docker/docker/libnetwork/types"
)

// addrSpace contains the pool configurations for the address space
type addrSpace struct {
	// Ordered list of allocated subnets. This field is used for linear subnet
	// allocations.
	allocated []netip.Prefix
	// Allocated subnets, indexed by their prefix. Values track address
	// allocations.
	subnets map[netip.Prefix]*PoolData

	// predefined pools for the address space
	predefined []*ipamutils.NetworkToSplit
	// Fisher-Yates shuffler used for random allocation of ULA subnets.
	shuffler *shuffler

	mu sync.Mutex
}

func newAddrSpace(predefined []*ipamutils.NetworkToSplit) (*addrSpace, error) {
	for i, p := range predefined {
		if !p.Base.IsValid() {
			return nil, errors.New("newAddrSpace: prefix zero found")
		}

		predefined[i].Base = p.Base.Masked()
	}

	slices.SortFunc(predefined, func(a, b *ipamutils.NetworkToSplit) int {
		return netiputil.Compare(a.Base, b.Base)
	})

	// We need to discard longer overlapping prefixes (sorted after the shorter
	// one), otherwise the dynamic allocator might consider a predefined
	// network is fully overlapped, go to the next one, which is a subnet of
	// the previous, and allocate from it.
	var last *ipamutils.NetworkToSplit
	var discarded int
	for i, imax := 0, len(predefined); i < imax; i++ {
		p := predefined[i-discarded]
		if last != nil && last.Overlaps(p.Base) {
			predefined = slices.Delete(predefined, i-discarded, i-discarded+1)
			discarded++
			continue
		}
		last = p
	}

	return &addrSpace{
		subnets:    map[netip.Prefix]*PoolData{},
		predefined: predefined,
	}, nil
}

// allocateSubnet adds the subnet k to the address space.
func (aSpace *addrSpace) allocateSubnet(nw, sub netip.Prefix) error {
	aSpace.mu.Lock()
	defer aSpace.mu.Unlock()

	// Check if already allocated
	if pool, ok := aSpace.subnets[nw]; ok {
		var childExists bool
		if sub != (netip.Prefix{}) {
			_, childExists = pool.children[sub]
		}
		if sub == (netip.Prefix{}) || childExists {
			// This means the same pool is already allocated. allocateSubnet is called when there
			// is request for a pool/subpool. It should ensure there is no overlap with existing pools
			return ipamapi.ErrPoolOverlap
		}
	}

	return aSpace.allocateSubnetL(nw, sub)
}

// allocateSubnetL takes a 'nw' parent prefix and a 'sub' prefix. These are
// '--subnet' and '--ip-range' on the CLI.
//
// If 'sub' prefix is specified, we don't check if 'parent' overlaps with
// existing allocations. However, if no 'sub' prefix is specified, we do check
// for overlaps. This behavior is weird and leads to the inconsistencies
// documented in https://github.com/moby/moby/issues/46756.
func (aSpace *addrSpace) allocateSubnetL(nw, sub netip.Prefix) error {
	// If master pool, check for overlap
	if sub == (netip.Prefix{}) {
		if aSpace.overlaps(nw) {
			return ipamapi.ErrPoolOverlap
		}
		return aSpace.allocatePool(nw)
	}

	// Look for parent pool
	_, ok := aSpace.subnets[nw]
	if !ok {
		if err := aSpace.allocatePool(nw); err != nil {
			return err
		}
		aSpace.subnets[nw].autoRelease = true
	}
	aSpace.subnets[nw].children[sub] = struct{}{}
	return nil
}

// overlaps reports whether nw contains any IP addresses in common with any of
// the existing subnets in this address space.
func (aSpace *addrSpace) overlaps(nw netip.Prefix) bool {
	for _, allocated := range aSpace.allocated {
		if allocated.Overlaps(nw) {
			return true
		}
	}
	return false
}

func (aSpace *addrSpace) allocatePool(nw netip.Prefix) error {
	for i, allocated := range aSpace.allocated {
		if nw.Addr().Compare(allocated.Addr()) < 0 {
			aSpace.allocated = slices.Insert(aSpace.allocated, i, nw)
			aSpace.subnets[nw] = newPoolData(nw)
			return nil
		}
	}

	aSpace.allocated = slices.Insert(aSpace.allocated, len(aSpace.allocated), nw)
	aSpace.subnets[nw] = newPoolData(nw)
	return nil
}

func (aSpace *addrSpace) allocatePredefinedPool(reserved []netip.Prefix) (netip.Prefix, error) {
	aSpace.mu.Lock()
	defer aSpace.mu.Unlock()

	var pdfID int
	var partialOverlap bool
	var prevAlloc netip.Prefix

	slices.SortFunc(reserved, netiputil.Compare)
	dc := newDoubleCursor(aSpace.allocated, reserved, func(a, b netip.Prefix) bool {
		return a.Addr().Less(b.Addr())
	})

	for {
		allocated := dc.Get()
		if allocated == (netip.Prefix{}) {
			// We reached the end of both 'aSpace.allocated' and 'reserved'.
			break
		}

		if pdfID >= len(aSpace.predefined) {
			return netip.Prefix{}, ipamapi.ErrNoMoreSubnets
		}
		pdf := aSpace.predefined[pdfID]

		if allocated.Overlaps(pdf.Base) {
			dc.Inc()

			if allocated.Bits() <= pdf.Base.Bits() {
				// The current 'allocated' prefix is bigger than the 'pdf'
				// network, thus the block is fully overlapped.
				partialOverlap = false
				prevAlloc = netip.Prefix{}
				pdfID++
				continue
			}

			// If no previous 'allocated' was found to partially overlap 'pdf',
			// we need to test whether there's enough space available at the
			// beginning of 'pdf'.
			if !partialOverlap && ipbits.Distance(pdf.FirstPrefix(), allocated, pdf.Size) >= 1 {
				// Okay, so there's at least a whole subnet available between
				// the start of 'pdf' and 'allocated'.
				next := pdf.FirstPrefix()
				aSpace.allocated = slices.Insert(aSpace.allocated, dc.ia, next)
				aSpace.subnets[next] = newPoolData(next)
				return next, nil
			}

			// If the network 'pdf' was already found to be partially
			// overlapped, we need to test whether there's enough space between
			// the end of 'prevAlloc' and current 'allocated'.
			afterPrev := netiputil.PrefixAfter(prevAlloc, pdf.Size)
			if partialOverlap && ipbits.Distance(afterPrev, allocated, pdf.Size) >= 1 {
				// Okay, so there's at least a whole subnet available after
				// 'prevAlloc' and before 'allocated'.
				aSpace.allocated = slices.Insert(aSpace.allocated, dc.ia, afterPrev)
				aSpace.subnets[afterPrev] = newPoolData(afterPrev)
				return afterPrev, nil
			}

			if netiputil.LastAddr(allocated) == netiputil.LastAddr(pdf.Base) {
				// The last address of the current 'allocated' prefix is the
				// same as the last address of the 'pdf' network, it's fully
				// overlapped.
				partialOverlap = false
				prevAlloc = netip.Prefix{}
				pdfID++
				continue
			}

			// This 'pdf' network is partially overlapped.
			partialOverlap = true
			prevAlloc = allocated
			continue
		}

		// Okay, so previous 'allocated' overlapped and current doesn't. Now
		// the question is: is there enough space left between previous
		// 'allocated' and the end of the 'pdf' network?
		if partialOverlap {
			partialOverlap = false

			if next := netiputil.PrefixAfter(prevAlloc, pdf.Size); pdf.Overlaps(next) {
				aSpace.allocated = slices.Insert(aSpace.allocated, dc.ia, next)
				aSpace.subnets[next] = newPoolData(next)
				return next, nil
			}

			// No luck, PrefixAfter yielded an invalid prefix. There's not
			// enough space left to subnet it once more.
			pdfID++

			// 'dc' is not incremented here, we need to re-test the current
			// 'allocated' against the next 'pdf' network.
			continue
		}

		// If the network 'pdf' doesn't overlap and is sorted before the
		// current 'allocated', we found the right spot.
		if pdf.Base.Addr().Less(allocated.Addr()) {
			next := netip.PrefixFrom(pdf.Base.Addr(), pdf.Size)
			aSpace.allocated = slices.Insert(aSpace.allocated, dc.ia, next)
			aSpace.subnets[next] = newPoolData(next)
			return aSpace.allocated[dc.ia], nil
		}

		dc.Inc()
		prevAlloc = allocated
	}

	if pdfID >= len(aSpace.predefined) {
		return netip.Prefix{}, ipamapi.ErrNoMoreSubnets
	}

	// We reached the end of 'allocated', but not the end of predefined
	// networks. Let's try two more times (once on the current 'pdf', and once
	// on the next network if any).
	if partialOverlap {
		pdf := aSpace.predefined[pdfID]

		if next := netiputil.PrefixAfter(prevAlloc, pdf.Size); pdf.Overlaps(next) {
			aSpace.allocated = slices.Insert(aSpace.allocated, dc.ia, next)
			aSpace.subnets[next] = newPoolData(next)
			return next, nil
		}

		// No luck -- PrefixAfter yielded an invalid prefix. There's not enough
		// space left.
		pdfID++
	}

	// One last chance. Here we don't increment pdfID since the last iteration
	// on 'dc' found either:
	//
	// - A full overlap, and incremented 'pdfID'.
	// - A partial overlap, and the previous 'if' incremented 'pdfID'.
	// - The current 'pdfID' comes after the last 'allocated' -- it's not
	//   overlapped at all.
	//
	// Hence, we're sure 'pdfID' has never been subnetted yet.
	if pdfID < len(aSpace.predefined) {
		pdf := aSpace.predefined[pdfID]

		next := pdf.FirstPrefix()
		aSpace.allocated = append(aSpace.allocated, next)
		aSpace.subnets[next] = newPoolData(next)
		return next, nil
	}

	return netip.Prefix{}, ipamapi.ErrNoMoreSubnets
}

func (aSpace *addrSpace) releaseSubnet(nw, sub netip.Prefix) error {
	aSpace.mu.Lock()
	defer aSpace.mu.Unlock()

	p, ok := aSpace.subnets[nw]
	if !ok {
		return ipamapi.ErrBadPool
	}

	if sub != (netip.Prefix{}) {
		if _, ok := p.children[sub]; !ok {
			return ipamapi.ErrBadPool
		}
		delete(p.children, sub)
	} else {
		p.autoRelease = true
	}

	if len(p.children) == 0 && p.autoRelease {
		aSpace.deallocate(nw)
	}

	return nil
}

// deallocate removes 'nw' from the list of allocations.
func (aSpace *addrSpace) deallocate(nw netip.Prefix) {
	for i, allocated := range aSpace.allocated {
		if allocated.Addr().Compare(nw.Addr()) == 0 && allocated.Bits() == nw.Bits() {
			aSpace.allocated = slices.Delete(aSpace.allocated, i, i+1)
			delete(aSpace.subnets, nw)
			return
		}
	}
}

func (aSpace *addrSpace) requestAddress(nw, sub netip.Prefix, prefAddress netip.Addr, opts map[string]string) (netip.Addr, error) {
	aSpace.mu.Lock()
	defer aSpace.mu.Unlock()

	p, ok := aSpace.subnets[nw]
	if !ok {
		return netip.Addr{}, types.NotFoundErrorf("cannot find address pool for poolID:%v/%v", nw, sub)
	}

	if prefAddress != (netip.Addr{}) && !nw.Contains(prefAddress) {
		return netip.Addr{}, ipamapi.ErrIPOutOfRange
	}

	if sub != (netip.Prefix{}) {
		if _, ok := p.children[sub]; !ok {
			return netip.Addr{}, types.NotFoundErrorf("cannot find address pool for poolID:%v/%v", nw, sub)
		}
	}

	// In order to request for a serial ip address allocation, callers can pass in the option to request
	// IP allocation serially or first available IP in the subnet
	serial := opts[ipamapi.AllocSerialPrefix] == "true"
	ip, err := getAddress(nw, p.addrs, prefAddress, sub, serial)
	if err != nil {
		return netip.Addr{}, err
	}

	return ip, nil
}

func (aSpace *addrSpace) releaseAddress(nw, sub netip.Prefix, address netip.Addr) error {
	aSpace.mu.Lock()
	defer aSpace.mu.Unlock()

	p, ok := aSpace.subnets[nw]
	if !ok {
		return types.NotFoundErrorf("cannot find address pool for %v/%v", nw, sub)
	}
	if sub != (netip.Prefix{}) {
		if _, ok := p.children[sub]; !ok {
			return types.NotFoundErrorf("cannot find address pool for poolID:%v/%v", nw, sub)
		}
	}

	if !address.IsValid() {
		return types.InvalidParameterErrorf("invalid address")
	}

	if !nw.Contains(address) {
		return ipamapi.ErrIPOutOfRange
	}

	defer log.G(context.TODO()).Debugf("Released address Address:%v Sequence:%s", address, p.addrs)

	return p.addrs.Unset(netiputil.HostID(address, uint(nw.Bits())))
}
