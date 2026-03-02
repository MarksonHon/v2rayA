package tun

import (
	"net/netip"
	"testing"
)

func TestIsReservedAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		// IPv4 reserved
		{"loopback", "127.0.0.1", true},
		{"loopback high", "127.255.255.255", true},
		{"private 10.x", "10.0.0.1", true},
		{"private 10.x high", "10.255.255.255", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 172.31.x", "172.31.255.255", true},
		{"private 192.168.x", "192.168.1.1", true},
		{"link-local", "169.254.1.1", true},
		{"multicast", "224.0.0.1", true},
		{"multicast high", "239.255.255.255", true},
		{"reserved 240.x", "240.0.0.1", true},
		{"current network", "0.0.0.0", true},
		// IPv4 not reserved
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 172.32.0.1", "172.32.0.1", false},
		{"public 172.15.0.1", "172.15.0.1", false},
		// IPv6 reserved
		{"ipv6 loopback", "::1", true},
		{"ipv6 link-local", "fe80::1", true},
		{"ipv6 ULA", "fc00::1", true},
		{"ipv6 ULA fd", "fd00::1", true},
		{"ipv6 multicast", "ff02::1", true},
		{"ipv6 unspecified", "::", true},
		// IPv6 not reserved
		{"ipv6 public", "2001:db8::1", false},
		// Invalid
		{"invalid", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				// For "not-an-ip", addr will be invalid
				if !isReservedAddress(addr) && !tt.expected {
					return
				}
				if isReservedAddress(addr) != tt.expected {
					t.Errorf("isReservedAddress(%q) = %v, want %v", tt.addr, isReservedAddress(addr), tt.expected)
				}
				return
			}
			if got := isReservedAddress(addr); got != tt.expected {
				t.Errorf("isReservedAddress(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestFilterTunDNSServers(t *testing.T) {
	tests := []struct {
		name     string
		servers  []netip.AddrPort
		expected int // expected count of filtered results
	}{
		{
			"empty",
			nil,
			0,
		},
		{
			"loopback only",
			[]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")},
			0,
		},
		{
			"unspecified only",
			[]netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:53")},
			0,
		},
		{
			"tun dns addr",
			[]netip.AddrPort{netip.MustParseAddrPort(dnsAddr + ":53")},
			0,
		},
		{
			"tun dns addr6",
			[]netip.AddrPort{netip.MustParseAddrPort("[" + dnsAddr6 + "]:53")},
			0,
		},
		{
			"public dns",
			[]netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:53")},
			1,
		},
		{
			"mixed",
			[]netip.AddrPort{
				netip.MustParseAddrPort("127.0.0.1:53"),
				netip.MustParseAddrPort("8.8.8.8:53"),
				netip.MustParseAddrPort(dnsAddr + ":53"),
				netip.MustParseAddrPort("1.1.1.1:53"),
			},
			2, // 8.8.8.8 and 1.1.1.1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterTunDNSServers(tt.servers)
			if len(result) != tt.expected {
				t.Errorf("filterTunDNSServers() returned %d servers, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestParseDNSServerHost(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		expected []string
	}{
		{"plain ip", "8.8.8.8", []string{"8.8.8.8"}},
		{"localhost", "localhost", []string{"127.0.0.1", "::1"}},
		{"ip with port", "1.1.1.1:53", []string{"1.1.1.1"}},
		{"https url", "https://dns.google/dns-query", []string{"dns.google"}},
		{"tls url", "tls://dns.google:853", []string{"dns.google"}},
		{"bare ipv6", "2001:db8::1", []string{"2001:db8::1"}},
		{"domain only", "dns.google", []string{"dns.google"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDNSServerHost(tt.server)
			if len(result) != len(tt.expected) {
				t.Errorf("parseDNSServerHost(%q) returned %d hosts, want %d: got %v", tt.server, len(result), len(tt.expected), result)
				return
			}
			for i, host := range result {
				if host != tt.expected[i] {
					t.Errorf("parseDNSServerHost(%q)[%d] = %q, want %q", tt.server, i, host, tt.expected[i])
				}
			}
		})
	}
}
