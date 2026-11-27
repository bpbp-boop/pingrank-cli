package accesspath

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Mapping struct {
	ExternalIPv4 netip.Addr
	ExternalPort uint16
	InternalPort uint16
	Conn         *net.UDPConn
	pcpNonce     [12]byte
	gateway      netip.Addr
}

func (m *Mapping) Close() {
	if m == nil {
		return
	}
	if m.Conn != nil {
		defer m.Conn.Close()
	}
	if m.gateway.IsValid() {
		_, _ = pcpMap(m.gateway, m.Conn, m.InternalPort, 0, m.pcpNonce)
	}
}

type RouterResult struct {
	ExternalIPv4 netip.Addr
	Source       string
	Status       string
	Mapping      *Mapping
}

func QueryRouter(ctx context.Context, local LocalState) RouterResult {
	if local.DefaultIPv4Gateway.IsValid() && local.LocalIPv4.IsValid() {
		if m, err := queryPCP(local.DefaultIPv4Gateway, local.LocalIPv4); err == nil {
			return RouterResult{ExternalIPv4: m.ExternalIPv4, Source: "pcp", Status: "ok", Mapping: m}
		}
		if a, err := queryNATPMP(local.DefaultIPv4Gateway); err == nil {
			return RouterResult{ExternalIPv4: a, Source: "nat-pmp", Status: "ok"}
		}
	}
	if a, err := queryUPnP(ctx, local.DefaultIPv4Gateway); err == nil {
		return RouterResult{ExternalIPv4: a, Source: "upnp", Status: "ok"}
	}
	return RouterResult{Status: "unavailable"}
}

func queryPCP(gateway, local netip.Addr) (*Mapping, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(local.AsSlice()), Port: 0})
	if err != nil {
		return nil, err
	}
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		conn.Close()
		return nil, err
	}
	m, err := pcpMap(gateway, conn, port, 60, nonce)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return m, nil
}

func pcpMap(gateway netip.Addr, conn *net.UDPConn, internalPort uint16, lifetime uint32, nonce [12]byte) (*Mapping, error) {
	if conn == nil {
		return nil, fmt.Errorf("pcp: no socket")
	}
	local := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if local == nil {
		return nil, fmt.Errorf("pcp: IPv4 required")
	}
	req := make([]byte, 60)
	req[0] = 2
	req[1] = 1
	binary.BigEndian.PutUint32(req[4:8], lifetime)
	copy(req[8:20], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
	copy(req[20:24], local)
	copy(req[24:36], nonce[:])
	req[36] = 17
	binary.BigEndian.PutUint16(req[40:42], internalPort)
	dst := &net.UDPAddr{IP: net.IP(gateway.AsSlice()), Port: 5351}
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := conn.WriteToUDP(req, dst); err != nil {
		return nil, err
	}
	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	if n < 60 || buf[0] != 2 || buf[1] != 0x81 || buf[3] != 0 {
		return nil, fmt.Errorf("pcp: invalid response")
	}
	if !bytes.Equal(buf[24:36], nonce[:]) {
		return nil, fmt.Errorf("pcp: nonce mismatch")
	}
	a, ok := netip.AddrFromSlice(buf[44:60])
	if !ok {
		return nil, fmt.Errorf("pcp: bad address")
	}
	a = a.Unmap()
	return &Mapping{ExternalIPv4: a, ExternalPort: binary.BigEndian.Uint16(buf[42:44]), InternalPort: internalPort, Conn: conn, pcpNonce: nonce, gateway: gateway}, nil
}

func queryNATPMP(gateway netip.Addr) (netip.Addr, error) {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	dst := &net.UDPAddr{IP: net.IP(gateway.AsSlice()), Port: 5351}
	if _, err = c.WriteToUDP([]byte{0, 0}, dst); err != nil {
		return netip.Addr{}, err
	}
	b := make([]byte, 32)
	n, _, err := c.ReadFromUDP(b)
	if err != nil {
		return netip.Addr{}, err
	}
	if n < 12 || b[0] != 0 || b[1] != 128 || binary.BigEndian.Uint16(b[2:4]) != 0 {
		return netip.Addr{}, fmt.Errorf("nat-pmp: invalid response")
	}
	return netip.AddrFrom4([4]byte{b[8], b[9], b[10], b[11]}), nil
}

type upnpRoot struct {
	Devices []upnpDevice `xml:"device"`
}
type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}
type upnpService struct {
	Type    string `xml:"serviceType"`
	Control string `xml:"controlURL"`
}

func validGatewayURL(raw string, gateway netip.Addr) (*url.URL, error) {
	if !gateway.IsValid() {
		return nil, fmt.Errorf("upnp: no gateway address")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upnp: invalid url: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return nil, fmt.Errorf("upnp: unsupported scheme %q", u.Scheme)
	}
	host, err := netip.ParseAddr(u.Hostname())
	if err != nil || host.Unmap() != gateway.Unmap() {
		return nil, fmt.Errorf("upnp: host %q does not match default gateway %s", u.Hostname(), gateway)
	}
	return u, nil
}

func validUPnPServiceType(s string) bool {
	if !strings.HasPrefix(s, "urn:schemas-upnp-org:service:WANIPConnection:") &&
		!strings.HasPrefix(s, "urn:schemas-upnp-org:service:WANPPPConnection:") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ':' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func queryUPnP(ctx context.Context, gateway netip.Addr) (netip.Addr, error) {
	if !gateway.IsValid() {
		return netip.Addr{}, fmt.Errorf("upnp: no default gateway")
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err = c.WriteToUDP([]byte(req), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != nil {
		return netip.Addr{}, err
	}
	b := make([]byte, 8192)
	n, _, err := c.ReadFromUDP(b)
	if err != nil {
		return netip.Addr{}, err
	}
	location := ""
	for _, line := range strings.Split(string(b[:n]), "\r\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "location") {
			location = strings.TrimSpace(v)
			break
		}
	}
	if location == "" {
		return netip.Addr{}, fmt.Errorf("upnp: no location")
	}
	base, err := validGatewayURL(location, gateway)
	if err != nil {
		return netip.Addr{}, err
	}
	hc := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return netip.Addr{}, err
	}
	var root upnpRoot
	if err = xml.Unmarshal(raw, &root); err != nil {
		return netip.Addr{}, err
	}
	service := findUPnPService(root.Devices)
	if service.Control == "" || !validUPnPServiceType(service.Type) {
		return netip.Addr{}, fmt.Errorf("upnp: WANIPConnection unavailable")
	}
	control, err := url.Parse(service.Control)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("upnp: invalid controlURL: %w", err)
	}
	endpointURL, err := validGatewayURL(base.ResolveReference(control).String(), gateway)
	if err != nil {
		return netip.Addr{}, err
	}
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddress xmlns:u="` + service.Type + `"></u:GetExternalIPAddress></s:Body></s:Envelope>`
	sreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL.String(), strings.NewReader(body))
	if err != nil {
		return netip.Addr{}, err
	}
	sreq.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	sreq.Header.Set("SOAPAction", `"`+service.Type+`#GetExternalIPAddress"`)
	sresp, err := hc.Do(sreq)
	if err != nil {
		return netip.Addr{}, err
	}
	defer sresp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(sresp.Body, 1<<20))
	if err != nil {
		return netip.Addr{}, err
	}
	var envelope struct {
		Address string `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	if err = xml.Unmarshal(out, &envelope); err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(strings.TrimSpace(envelope.Address))
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

func findUPnPService(devices []upnpDevice) upnpService {
	for _, d := range devices {
		for _, s := range d.Services {
			if strings.Contains(s.Type, "WANIPConnection") || strings.Contains(s.Type, "WANPPPConnection") {
				return s
			}
		}
		if s := findUPnPService(d.Devices); s.Control != "" {
			return s
		}
	}
	return upnpService{}
}
