package accesspath

import (
	"context"
	"net"
	"net/netip"
	"time"
)

func Measure(ctx context.Context, reflectors []Reflector) (Result, error) {
	local, err := CollectLocalState()
	if err != nil {
		return Result{}, err
	}
	router := QueryRouter(ctx, local)
	if router.Mapping != nil {
		defer router.Mapping.Close()
	}
	m := Measurements{LocalIPv4Available: local.LocalIPv4.IsValid(), LocalIPv4Global: local.LocalIPv4.IsValid() && local.LocalIPv4.IsGlobalUnicast() && !local.LocalIPv4.IsPrivate(), NativeIPv4Available: local.LocalIPv4.IsValid() && addressCategory(local.LocalIPv4) != "service-continuity", GlobalIPv6Available: globalIPv6Prefix(local.LocalIPv6) != "", IPv6Prefix: globalIPv6Prefix(local.LocalIPv6), RouterExternalSource: router.Source, RouterQueryStatus: router.Status, TestedAt: time.Now().UTC()}
	if router.ExternalIPv4.IsValid() {
		m.RouterExternalIPv4 = router.ExternalIPv4.String()
	}
	for i, r := range reflectors {
		var u Observation
		var uerr error
		if i == 0 && router.Mapping != nil {
			u, uerr = observeUDP(ctx, r, router.Mapping.Conn, nil)
		} else {
			u, uerr = observeUDP(ctx, r, nil, nil)
		}
		if uerr == nil {
			m.Observations = append(m.Observations, u)
			m.IPv4Works = m.IPv4Works || u.PublicIPv4 != ""
			if m.ObservedPublicIPv4 == "" {
				m.ObservedPublicIPv4 = u.PublicIPv4
			}
			if m.ObservedPublicIPv6 == "" {
				m.ObservedPublicIPv6 = u.PublicIPv6
			}
			if i == 0 && router.Mapping != nil && u.PublicIPv4 != "" {
				m.ExplicitMappingRemapped = router.Mapping.ExternalIPv4.String() != u.PublicIPv4 || int(router.Mapping.ExternalPort) != u.PublicPort
			}
		}
		for _, network := range []string{"tcp4", "tcp6"} {
			if o, e := observeTCP(ctx, r, network); e == nil {
				m.Observations = append(m.Observations, o)
				m.IPv4Works = m.IPv4Works || o.PublicIPv4 != ""
				if m.ObservedPublicIPv4 == "" {
					m.ObservedPublicIPv4 = o.PublicIPv4
				}
				if m.ObservedPublicIPv6 == "" {
					m.ObservedPublicIPv6 = o.PublicIPv6
				}
			}
			if o, e := observeHTTPS(ctx, r, network); e == nil {
				m.Observations = append(m.Observations, o)
				m.IPv4Works = m.IPv4Works || o.PublicIPv4 != ""
				if m.ObservedPublicIPv4 == "" {
					m.ObservedPublicIPv4 = o.PublicIPv4
				}
				if m.ObservedPublicIPv6 == "" {
					m.ObservedPublicIPv6 = o.PublicIPv6
				}
			}
		}
	}
	if p, e := discoverPREF64(ctx); e == nil {
		m.PREF64 = p.String()
		m.PREF64DiscoveryMethod = "dns_ipv4only_arpa"
		for _, r := range reflectors {
			v4, port, e := firstIPv4(r.UDP)
			if e != nil {
				continue
			}
			synth, ok := synthesize(p, v4)
			if !ok {
				continue
			}
			dst := &net.UDPAddr{IP: net.IP(synth.AsSlice()), Port: int(port)}
			if o, e := observeUDP(ctx, r, nil, dst); e == nil && o.PublicIPv4 != "" {
				m.NAT64Verified = true
				break
			}
		}
	}
	return Classify(m), nil
}

func ParseObservedAddr(s string) netip.Addr { a, _ := netip.ParseAddr(s); return a }
