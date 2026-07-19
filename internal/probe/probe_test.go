package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

// TestICMPv6StructLayouts pins the Windows struct sizes the ICMPv6 syscalls
// depend on. IPV6_ADDRESS_EX is pack(1) (26 bytes) inside a naturally-aligned
// reply, so two pad bytes precede Status -> 36 bytes. If these drift, echo6
// reads garbage RTT/status and IPv6 probing silently fails.
func TestICMPv6StructLayouts(t *testing.T) {
	if got := unsafe.Sizeof(sockaddrIn6{}); got != 28 {
		t.Fatalf("sockaddr_in6 size = %d, want 28", got)
	}
	if got := unsafe.Sizeof(icmpv6EchoReply{}); got != 36 {
		t.Fatalf("ICMPV6_ECHO_REPLY size = %d, want 36", got)
	}
	// Status/RoundTripTime sit after the packed 26-byte address + 2 pad bytes.
	if off := unsafe.Offsetof(icmpv6EchoReply{}.Status); off != 28 {
		t.Fatalf("Status offset = %d, want 28", off)
	}
}

// TestICMPv6ReplyAddr checks the sin6_addr extraction from the packed
// IPV6_ADDRESS_EX (bytes 6..21 within the address field).
func TestICMPv6ReplyAddr(t *testing.T) {
	want := netip.MustParseAddr("2001:db8::4")
	var rep icmpv6EchoReply
	binary.BigEndian.PutUint16(rep.Address[0:2], 27015) // sin6_port (ignored)
	copy(rep.Address[6:22], want.AsSlice())             // sin6_addr
	if got := rep.addr(); got != want {
		t.Fatalf("reply addr = %s, want %s", got, want)
	}
}
