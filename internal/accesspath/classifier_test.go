package accesspath

import (
	"testing"
	"time"
)

func TestClassifyAccessPaths(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name              string
		m                 Measurements
		class, confidence string
	}{
		{"native", Measurements{LocalIPv4Global: true, ObservedPublicIPv4: "203.0.113.1", TestedAt: now}, NativePublicIPv4, ConfidenceStrong},
		{"home nat", Measurements{RouterExternalIPv4: "8.8.8.8", ObservedPublicIPv4: "8.8.8.8", TestedAt: now}, HomeNATOnly, ConfidenceSuggestive},
		{"cgnat", Measurements{RouterExternalIPv4: "100.72.1.2", RouterExternalSource: "pcp", ObservedPublicIPv4: "8.8.8.8", TestedAt: now}, UpstreamNAT44, ConfidenceStrong},
		{"nat64", Measurements{PREF64: "64:ff9b::/96", NAT64Verified: true, TestedAt: now}, NAT64, ConfidenceConfirmed},
		{"464xlat", Measurements{PREF64: "64:ff9b::/96", NAT64Verified: true, IPv4Works: true, NativeIPv4Available: false, TestedAt: now}, Likely464XLAT, ConfidenceStrong},
		{"inconclusive", Measurements{RouterQueryStatus: "unavailable", ObservedPublicIPv4: "8.8.8.8", TestedAt: now}, Indeterminate, ConfidenceUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.m)
			if got.Classification != tt.class || got.Confidence != tt.confidence {
				t.Fatalf("got %s/%s want %s/%s: %+v", got.Classification, got.Confidence, tt.class, tt.confidence, got)
			}
		})
	}
}
