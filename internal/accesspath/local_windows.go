package accesspath

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

type LocalState struct {
	LocalIPv4          netip.Addr
	LocalIPv6          []netip.Addr
	DefaultIPv4Gateway netip.Addr
	DefaultIPv6Gateway netip.Addr
	DNSServers         []netip.Addr
	InterfaceType      string
}

func CollectLocalState() (LocalState, error) {
	const familyUnspec = 0
	flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_PREFIX)
	var size uint32
	err := windows.GetAdaptersAddresses(familyUnspec, flags, 0, nil, &size)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return LocalState{}, fmt.Errorf("GetAdaptersAddresses(size): %w", err)
	}
	buf := make([]byte, size)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(familyUnspec, flags, 0, first, &size); err != nil {
		return LocalState{}, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	var chosen *windows.IpAdapterAddresses
	best := ^uint32(0)
	for a := first; a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.FirstGatewayAddress == nil {
			continue
		}
		metric := a.Ipv4Metric
		if metric < best {
			chosen, best = a, metric
		}
	}
	if chosen == nil {
		return LocalState{}, fmt.Errorf("no active default-route adapter")
	}
	s := LocalState{InterfaceType: interfaceType(chosen.IfType)}
	for u := chosen.FirstUnicastAddress; u != nil; u = u.Next {
		if addr, ok := socketAddr(u.Address); ok {
			if addr.Is4() && !addr.IsLinkLocalUnicast() && !s.LocalIPv4.IsValid() {
				s.LocalIPv4 = addr
			}
			if addr.Is6() && !addr.IsLinkLocalUnicast() && !addr.IsLoopback() {
				s.LocalIPv6 = append(s.LocalIPv6, addr)
			}
		}
	}
	for g := chosen.FirstGatewayAddress; g != nil; g = g.Next {
		if addr, ok := socketAddr(g.Address); ok {
			if addr.Is4() && !s.DefaultIPv4Gateway.IsValid() {
				s.DefaultIPv4Gateway = addr
			}
			if addr.Is6() && !s.DefaultIPv6Gateway.IsValid() {
				s.DefaultIPv6Gateway = addr
			}
		}
	}
	for d := chosen.FirstDnsServerAddress; d != nil; d = d.Next {
		if addr, ok := socketAddr(d.Address); ok {
			s.DNSServers = append(s.DNSServers, addr)
		}
	}
	return s, nil
}

func socketAddr(sa windows.SocketAddress) (netip.Addr, bool) {
	ip := sa.IP()
	if ip == nil {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok
}

func interfaceType(t uint32) string {
	switch t {
	case windows.IF_TYPE_ETHERNET_CSMACD:
		return "ethernet"
	case windows.IF_TYPE_IEEE80211:
		return "wifi"
	case windows.IF_TYPE_PPP:
		return "ppp"
	case windows.IF_TYPE_TUNNEL:
		return "tunnel"
	default:
		return "other"
	}
}

func globalIPv6Prefix(addrs []netip.Addr) string {
	for _, a := range addrs {
		if a.Is6() && a.IsGlobalUnicast() && !a.IsPrivate() {
			return netip.PrefixFrom(a, 48).Masked().String()
		}
	}
	return ""
}
