package accesspath

import (
	"net/netip"
	"testing"
)

func TestValidGatewayURL(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	if _, err := validGatewayURL("http://192.168.1.1:5000/rootDesc.xml", gw); err != nil {
		t.Fatalf("valid gateway URL rejected: %v", err)
	}
	for _, bad := range []string{
		"http://127.0.0.1:8080/admin",
		"http://192.168.1.2:5000/rootDesc.xml",
		"https://192.168.1.1/rootDesc.xml",
		"file:///C:/Windows/win.ini",
		"http://evil.example/rootDesc.xml",
		"://bad-url",
	} {
		if _, err := validGatewayURL(bad, gw); err == nil {
			t.Fatalf("untrusted URL %q was accepted", bad)
		}
	}
}

func TestValidUPnPServiceType(t *testing.T) {
	if !validUPnPServiceType("urn:schemas-upnp-org:service:WANIPConnection:1") {
		t.Fatal("valid WANIPConnection:1 rejected")
	}
	if !validUPnPServiceType("urn:schemas-upnp-org:service:WANPPPConnection:1") {
		t.Fatal("valid WANPPPConnection:1 rejected")
	}
	for _, bad := range []string{
		`urn:schemas-upnp-org:service:WANIPConnection:1"><evil/>`,
		"urn:schemas-upnp-org:service:WANIPConnection:1\r\nX-Injected: 1",
		"urn:other:service:Foo:1",
	} {
		if validUPnPServiceType(bad) {
			t.Fatalf("malicious service type %q was accepted", bad)
		}
	}
}
