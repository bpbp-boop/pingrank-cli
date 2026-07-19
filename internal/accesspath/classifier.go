package accesspath

import "net/netip"

func Classify(m Measurements) Result {
	r := Result{
		Classification: Indeterminate, Confidence: ConfidenceUnknown,
		LocalIPv4Available: m.LocalIPv4Available, GlobalIPv6Available: m.GlobalIPv6Available,
		IPv6Prefix: m.IPv6Prefix, RouterExternalIPv4: m.RouterExternalIPv4,
		RouterExternalSource: m.RouterExternalSource, RouterQueryStatus: m.RouterQueryStatus,
		ObservedPublicIPv4: m.ObservedPublicIPv4, ObservedPublicIPv6: m.ObservedPublicIPv6,
		NAT64Prefix: m.PREF64, PREF64DiscoveryMethod: m.PREF64DiscoveryMethod,
		Observations: m.Observations, TestedAt: m.TestedAt,
		ClassifierVersion: ClassifierVersion,
	}
	add := func(code, source string) { r.Evidence = append(r.Evidence, EvidenceItem{Type: code, Source: source}) }
	if m.PREF64 != "" {
		source := m.PREF64DiscoveryMethod
		if source == "" {
			source = "dns"
		}
		add(EvidencePREF64, source)
	}
	if m.NAT64Verified {
		add(EvidenceNAT64Verified, "reflector")
	}
	if m.NAT64Verified && m.IPv4Works && !m.NativeIPv4Available {
		add(EvidenceIPv4OverIPv6Only, "socket")
		r.Classification, r.Confidence = Likely464XLAT, ConfidenceStrong
		return r
	}
	if m.NAT64Verified {
		r.Classification, r.Confidence = NAT64, ConfidenceConfirmed
		return r
	}
	if m.RouterReportsDSLite {
		add(EvidenceRouterDSLite, "router")
		r.Classification, r.Confidence = LikelyDSLite, ConfidenceStrong
		return r
	}
	if m.RouterReportsMAP {
		add(EvidenceRouterMAP, "router")
		r.Classification, r.Confidence = LikelyAddressPortSharing, ConfidenceStrong
		return r
	}
	if m.RestrictedPortSet {
		add(EvidenceRestrictedPorts, "reflectors")
		r.Classification, r.Confidence = LikelyAddressPortSharing, ConfidenceSuggestive
		return r
	}
	router, routerOK := netip.ParseAddr(m.RouterExternalIPv4)
	observed, observedOK := netip.ParseAddr(m.ObservedPublicIPv4)
	if routerOK == nil && observedOK == nil && addressCategory(observed) == "global" {
		category := addressCategory(router)
		if category != "global" {
			switch category {
			case "rfc1918":
				add(EvidenceRouterRFC1918, m.RouterExternalSource)
			case "shared":
				add(EvidenceRouterSharedUse, m.RouterExternalSource)
			case "service-continuity":
				add(EvidenceRouterServiceContinuity, m.RouterExternalSource)
			}
			add(EvidenceAddressesDiffer, "classifier")
			r.Classification, r.Confidence = UpstreamNAT44, ConfidenceStrong
			return r
		}
		if router != observed {
			add(EvidenceAddressesDiffer, "classifier")
			r.Classification, r.Confidence = UpstreamNAT44, ConfidenceStrong
			return r
		}
		add(EvidenceAddressesMatch, "classifier")
		r.Classification, r.Confidence = HomeNATOnly, ConfidenceSuggestive
		return r
	}
	if m.ExplicitMappingRemapped {
		add(EvidenceMappingRemapped, "pcp")
		r.Classification, r.Confidence = UpstreamNAT44, ConfidenceStrong
		return r
	}
	if m.LocalIPv4Global && observedOK == nil && addressCategory(observed) == "global" {
		add(EvidenceLocalPublicIPv4, "interface")
		r.Classification, r.Confidence = NativePublicIPv4, ConfidenceStrong
		return r
	}
	if m.SpecialUseHop {
		add(EvidenceSpecialHop, "trace")
		r.Classification, r.Confidence = TranslatedAccessUnknown, ConfidenceSuggestive
		return r
	}
	if m.RouterQueryStatus == "unavailable" || m.RouterExternalIPv4 == "" {
		add(EvidenceRouterUnavailable, "router")
	}
	return r
}

func addressCategory(addr netip.Addr) string {
	if !addr.Is4() {
		return "other"
	}
	b := addr.As4()
	switch {
	case b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168):
		return "rfc1918"
	case b[0] == 100 && b[1] >= 64 && b[1] <= 127:
		return "shared"
	case b[0] == 192 && b[1] == 0 && b[2] == 0 && b[3] <= 7:
		return "service-continuity"
	case addr.IsGlobalUnicast():
		return "global"
	default:
		return "other"
	}
}

func Explanation(r Result) string {
	switch r.Classification {
	case UpstreamNAT44:
		return "Your router and the Internet reflector reported different IPv4 address layers. This is strong evidence of upstream address translation."
	case HomeNATOnly:
		return "No upstream address translation was detected. This does not prove that address sharing is absent."
	case NativePublicIPv4:
		return "This device appears to have a directly usable public IPv4 path."
	case NAT64:
		return "A discovered NAT64 prefix successfully translated an IPv6 connection to an IPv4 reflector."
	case Likely464XLAT:
		return "NAT64 was verified and ordinary IPv4 sockets work without a visible native IPv4 path, which is consistent with 464XLAT."
	case LikelyDSLite:
		return "The router exposed DS-Lite configuration evidence."
	case LikelyAddressPortSharing:
		return "The available mapping evidence is consistent with address-and-port sharing."
	case TranslatedAccessUnknown:
		return "Translation evidence was observed, but the mechanism could not be identified safely."
	default:
		return "The available measurements are inconclusive. Missing router information is not evidence for or against CGNAT."
	}
}
