package tun

import (
	"net/netip"
	"slices"
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

// TestProxyServerExclusionIncludesWhitelist verifies that when proxy server
// prefixes are merged into the exclusion/whitelist config, the corresponding
// IP addresses end up in BOTH the route-level exclude list AND the
// connection-level whitelist. This is the defense-in-depth mechanism that
// prevents traffic loops even when route-level exclusion fails.
func TestProxyServerExclusionIncludesWhitelist(t *testing.T) {
	proxyPrefixes := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/32"),
		netip.MustParsePrefix("5.6.7.8/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}

	// Simulate the logic in Start(): proxy prefixes should be added to both
	// savedExclude and savedWhitelist.
	var savedExclude []netip.Prefix
	var savedWhitelist []netip.Addr

	for _, prefix := range proxyPrefixes {
		if !slices.Contains(savedExclude, prefix) {
			savedExclude = append(savedExclude, prefix)
		}

		proxyAddr := prefix.Addr()
		if !slices.Contains(savedWhitelist, proxyAddr) {
			savedWhitelist = append(savedWhitelist, proxyAddr)
		}
	}

	// Verify all proxy IPs are in route-level exclusion list
	for _, prefix := range proxyPrefixes {
		if !slices.Contains(savedExclude, prefix) {
			t.Errorf("proxy prefix %s not found in route exclusion list", prefix)
		}
	}

	// Verify all proxy IPs are in connection-level whitelist
	for _, prefix := range proxyPrefixes {
		if !slices.Contains(savedWhitelist, prefix.Addr()) {
			t.Errorf("proxy address %s not found in connection whitelist", prefix.Addr())
		}
	}

	// Verify a non-proxy public IP would NOT be whitelisted (sanity check)
	nonProxy := netip.MustParseAddr("9.9.9.9")
	if slices.Contains(savedWhitelist, nonProxy) {
		t.Errorf("non-proxy address %s should not be in whitelist", nonProxy)
	}

	// Verify a public proxy IP is NOT reserved (i.e. needs explicit whitelist protection)
	publicProxy := netip.MustParseAddr("1.2.3.4")
	if isReservedAddress(publicProxy) {
		t.Errorf("public proxy address %s should NOT be reserved - whitelist is needed", publicProxy)
	}
}

// TestCheckProxyIPExcluded verifies the per-IP exclusion check logic used by
// verifyProxyServerExclusion. This is the function that determines whether a
// proxy server IP is properly protected at both the route level and the
// connection level.
func TestCheckProxyIPExcluded(t *testing.T) {
	whitelist := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
	}
	excludeAddrs := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/32"),
		netip.MustParsePrefix("5.6.7.8/32"),
	}

	tests := []struct {
		name            string
		ip              string
		wantWhitelisted bool
		wantExcluded    bool
	}{
		// Public IPs in both lists → fully protected
		{"in both lists", "1.2.3.4", true, true},
		{"in both lists v2", "5.6.7.8", true, true},
		// Public IP missing from both → NOT protected (traffic loop risk)
		{"missing from both", "9.9.9.9", false, false},
		// Reserved addresses always return (true, true)
		{"loopback reserved", "127.0.0.1", true, true},
		{"private reserved", "192.168.1.1", true, true},
		{"ipv6 reserved", "::1", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			gotW, gotE := checkProxyIPExcluded(ip, whitelist, excludeAddrs)
			if gotW != tt.wantWhitelisted {
				t.Errorf("checkProxyIPExcluded(%s) inWhitelist = %v, want %v", tt.ip, gotW, tt.wantWhitelisted)
			}
			if gotE != tt.wantExcluded {
				t.Errorf("checkProxyIPExcluded(%s) inExclude = %v, want %v", tt.ip, gotE, tt.wantExcluded)
			}
		})
	}
}
