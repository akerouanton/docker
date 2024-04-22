// Package ipbits contains utilities for manipulating [netip.Addr] values as
// numbers or bitfields.
package ipbits

import (
	"encoding/binary"
	"net/netip"
)

// Add returns ip + (x << shift).
func Add(ip netip.Addr, x uint64, shift uint) netip.Addr {
	if ip.Is4() {
		a := ip.As4()
		addr := binary.BigEndian.Uint32(a[:])
		addr += uint32(x) << shift
		binary.BigEndian.PutUint32(a[:], addr)
		return netip.AddrFrom4(a)
	} else {
		a := ip.As16()
		addr := uint128From16(a)
		addr = addr.add(uint128From(x).lsh(shift))
		addr.fill16(&a)
		return netip.AddrFrom16(a)
	}
}

// Sub returns ip - (x << shift).
func Sub(ip netip.Addr, x uint64, shift uint) netip.Addr {
	if ip.Is4() {
		a := ip.As4()
		addr := binary.BigEndian.Uint32(a[:])
		addr -= uint32(x) << shift
		binary.BigEndian.PutUint32(a[:], addr)
		return netip.AddrFrom4(a)
	} else {
		a := ip.As16()
		addr := uint128From16(a)
		addr = addr.sub(uint128From(x).lsh(shift))
		addr.fill16(&a)
		return netip.AddrFrom16(a)
	}
}

// Distance computes the number of subnets of size 'sz' available between 'p1'
// and 'p2'. The result is capped at [math.MaxUint64]. It returns 0 when one of
// 'p1' or 'p2' is invalid, if both aren't of the same family, or when 'p2' is
// less than 'p2'.
func Distance(p1 netip.Prefix, p2 netip.Prefix, sz int) uint64 {
	if !p1.IsValid() || !p2.IsValid() || p1.Addr().Is4() != p2.Addr().Is4() || p2.Addr().Less(p1.Addr()) {
		return 0
	}

	p1 = netip.PrefixFrom(p1.Addr(), sz).Masked()
	p2 = netip.PrefixFrom(p2.Addr(), sz).Masked()

	return subAddr(p2.Addr(), p1.Addr()).rsh(uint(p1.Addr().BitLen() - sz)).uint64()
}

// subAddr returns 'ip1 - ip2'. Both netip.Addr have to be of the same address
// family. 'ip1' as to be greater than or equal to 'ip2'.
func subAddr(ip1 netip.Addr, ip2 netip.Addr) uint128 {
	if ip1.Is4() {
		a1 := ip1.As4()
		a2 := ip2.As4()
		addr1 := binary.BigEndian.Uint32(a1[:])
		addr2 := binary.BigEndian.Uint32(a2[:])
		return uint128From(uint64(addr1 - addr2))
	} else {
		addr1 := uint128From16(ip1.As16())
		addr2 := uint128From16(ip2.As16())
		return addr1.sub(addr2)
	}
}

// Field returns the value of the bitfield [u, v] in ip as an integer,
// where bit 0 is the most-significant bit of ip.
//
// The result is undefined if u > v, if v-u > 64, or if u or v is larger than
// ip.BitLen().
func Field(ip netip.Addr, u, v uint) uint64 {
	if ip.Is4() {
		mask := ^uint32(0) >> u
		a := ip.As4()
		return uint64((binary.BigEndian.Uint32(a[:]) & mask) >> (32 - v))
	} else {
		mask := uint128From(0).not().rsh(u)
		return uint128From16(ip.As16()).and(mask).rsh(128 - v).uint64()
	}
}
