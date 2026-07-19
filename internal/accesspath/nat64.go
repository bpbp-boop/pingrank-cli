package accesspath

import (
	"context"
	"net"
	"net/netip"
)

func discoverPREF64(ctx context.Context) (netip.Prefix, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", "ipv4only.arpa")
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, a := range addrs {
		if p, ok := prefixFromIPv4Only(a); ok {
			return p, nil
		}
	}
	return netip.Prefix{}, &net.DNSError{Err: "no synthesized ipv4only.arpa address", Name: "ipv4only.arpa"}
}

func prefixFromIPv4Only(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.Is6() {
		return netip.Prefix{}, false
	}
	for _, bits := range []int{96, 64, 56, 48, 40, 32} {
		v4, ok := extractIPv4(addr.As16(), bits)
		if ok && (v4 == [4]byte{192, 0, 0, 170} || v4 == [4]byte{192, 0, 0, 171}) {
			return netip.PrefixFrom(addr, bits).Masked(), true
		}
	}
	return netip.Prefix{}, false
}

func synthesize(prefix netip.Prefix, v4 netip.Addr) (netip.Addr, bool) {
	if !prefix.Addr().Is6() || !v4.Is4() {
		return netip.Addr{}, false
	}
	b := prefix.Addr().As16()
	x := v4.As4()
	if !insertIPv4(&b, prefix.Bits(), x) {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16(b), true
}

// RFC 6052 places an IPv4 address either directly after a /96 or split around
// the reserved u octet (byte 8) for the shorter well-known prefix lengths.
func insertIPv4(dst *[16]byte, bits int, v4 [4]byte) bool {
	start := bits / 8
	switch bits {
	case 96:
		copy(dst[12:16], v4[:])
	case 64:
		dst[8] = 0
		copy(dst[9:13], v4[:])
	case 56, 48, 40, 32:
		before := 8 - start
		copy(dst[start:8], v4[:before])
		dst[8] = 0
		copy(dst[9:9+4-before], v4[before:])
	default:
		return false
	}
	return true
}

func extractIPv4(src [16]byte, bits int) ([4]byte, bool) {
	var out [4]byte
	start := bits / 8
	switch bits {
	case 96:
		copy(out[:], src[12:16])
	case 64:
		if src[8] != 0 {
			return out, false
		}
		copy(out[:], src[9:13])
	case 56, 48, 40, 32:
		if src[8] != 0 {
			return out, false
		}
		before := 8 - start
		copy(out[:before], src[start:8])
		copy(out[before:], src[9:9+4-before])
	default:
		return out, false
	}
	return out, true
}
