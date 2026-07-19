package accesspath

import (
	"net/netip"
	"testing"
)

func TestNAT64RFC6052PrefixLengths(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.0.170")
	for _, prefixText := range []string{
		"2001:db8::/32", "2001:db8:1200::/40", "2001:db8:1234::/48",
		"2001:db8:1234:5600::/56", "2001:db8:1234:5678::/64", "64:ff9b::/96",
	} {
		t.Run(prefixText, func(t *testing.T) {
			prefix := netip.MustParsePrefix(prefixText).Masked()
			synthesized, ok := synthesize(prefix, v4)
			if !ok {
				t.Fatal("synthesis failed")
			}
			discovered, ok := prefixFromIPv4Only(synthesized)
			if !ok || discovered != prefix {
				t.Fatalf("discovered %v, %t; want %v", discovered, ok, prefix)
			}
		})
	}
}

func TestNAT64RejectsOrdinaryIPv6(t *testing.T) {
	if _, ok := prefixFromIPv4Only(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("ordinary IPv6 address treated as synthesized ipv4only.arpa")
	}
}
