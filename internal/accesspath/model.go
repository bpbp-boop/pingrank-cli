package accesspath

import "time"

const ClassifierVersion = 1

const (
	NativePublicIPv4         = "native_public_ipv4"
	HomeNATOnly              = "home_nat_only"
	UpstreamNAT44            = "upstream_nat44"
	NAT64                    = "nat64"
	Likely464XLAT            = "likely_464xlat"
	LikelyDSLite             = "likely_ds_lite"
	LikelyAddressPortSharing = "likely_address_port_sharing"
	TranslatedAccessUnknown  = "translated_access_unknown"
	Indeterminate            = "indeterminate"

	ConfidenceConfirmed  = "confirmed"
	ConfidenceStrong     = "strong"
	ConfidenceSuggestive = "suggestive"
	ConfidenceUnknown    = "unknown"
)

const (
	EvidenceRouterRFC1918           = "router_address_is_rfc1918"
	EvidenceRouterSharedUse         = "router_address_is_shared_use"
	EvidenceRouterServiceContinuity = "router_address_is_service_continuity"
	EvidenceAddressesDiffer         = "router_and_reflector_addresses_differ"
	EvidenceMappingRemapped         = "explicit_mapping_remapped_upstream"
	EvidencePREF64                  = "pref64_discovered"
	EvidenceNAT64Verified           = "nat64_connection_verified"
	EvidenceIPv4OverIPv6Only        = "ipv4_socket_works_over_ipv6_only_access"
	EvidenceSpecialHop              = "special_use_hop_seen_after_gateway"
	EvidenceRestrictedPorts         = "restricted_source_port_set"
	EvidenceSharedPublicIPv4        = "concurrent_agents_share_public_ipv4"
	EvidenceRouterDSLite            = "router_reports_ds_lite"
	EvidenceRouterMAP               = "router_reports_map"
	EvidenceRouterUnavailable       = "router_information_unavailable"
	EvidenceAddressesMatch          = "router_and_reflector_addresses_match"
	EvidenceLocalPublicIPv4         = "local_public_ipv4_observed"
)

type EvidenceItem struct {
	Type   string `json:"type"`
	Source string `json:"source,omitempty"`
}

type Observation struct {
	PublicIPv4  string `json:"publicIpv4,omitempty"`
	PublicPort  int    `json:"publicPort,omitempty"`
	PublicIPv6  string `json:"publicIpv6,omitempty"`
	Transport   string `json:"transport"`
	ReflectorID string `json:"reflectorId"`
}

type Result struct {
	Classification        string         `json:"classification"`
	Confidence            string         `json:"confidence"`
	LocalIPv4Available    bool           `json:"localIpv4Available"`
	GlobalIPv6Available   bool           `json:"globalIpv6Available"`
	IPv6Prefix            string         `json:"ipv6Prefix,omitempty"`
	RouterExternalIPv4    string         `json:"routerExternalIpv4,omitempty"`
	RouterExternalSource  string         `json:"routerExternalSource,omitempty"`
	RouterQueryStatus     string         `json:"routerExternalQueryStatus,omitempty"`
	ObservedPublicIPv4    string         `json:"observedPublicIpv4,omitempty"`
	ObservedPublicIPv6    string         `json:"observedPublicIpv6,omitempty"`
	NAT64Prefix           string         `json:"nat64Prefix,omitempty"`
	PREF64DiscoveryMethod string         `json:"pref64DiscoveryMethod,omitempty"`
	Evidence              []EvidenceItem `json:"evidence"`
	Observations          []Observation  `json:"observations,omitempty"`
	TestedAt              time.Time      `json:"testedAt"`
	ClassifierVersion     int            `json:"classifierVersion"`
}

type Measurements struct {
	LocalIPv4Available      bool
	LocalIPv4Global         bool
	GlobalIPv6Available     bool
	IPv6Prefix              string
	RouterExternalIPv4      string
	RouterExternalSource    string
	RouterQueryStatus       string
	ObservedPublicIPv4      string
	ObservedPublicIPv6      string
	Observations            []Observation
	PREF64                  string
	PREF64DiscoveryMethod   string
	NAT64Verified           bool
	IPv4Works               bool
	NativeIPv4Available     bool
	ExplicitMappingRemapped bool
	SpecialUseHop           bool
	RouterReportsDSLite     bool
	RouterReportsMAP        bool
	RestrictedPortSet       bool
	TestedAt                time.Time
}
