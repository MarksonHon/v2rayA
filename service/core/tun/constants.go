package tun

const (
	// TunDNSListenPort is the local dokodemo-door port used by TUN DNS forwarding.
	TunDNSListenPort = 6053

	// TunMark is the socket mark applied to both the hev-socks5-tunnel helper's
	// outbound SOCKS5 connections and to v2ray's outbound connections when running
	// in HevTun mode.  The Linux policy-routing rule "fwmark TunMark → lookup main"
	// exempts these packets from being re-captured by the TUN device, preventing
	// the traffic-loop that would otherwise occur.
	TunMark = 438

	// Default values for Hev socks5 tunnel config.
	defaultTunName = "v2raya-tun"
	defaultIPv4    = "198.18.0.1"
	defaultIPv6    = "fc00::1"
	defaultMapDNS  = "198.18.0.2"
	defaultMTU     = 8500
	defaultMark    = TunMark

	// defaultMapDNSNetwork / defaultMapDNSNetmask define the CGNAT address pool
	// (RFC 6598, 100.64.0.0/10) used by hev-socks5-tunnel's MapDNS feature to
	// assign fake IP addresses.  This range does NOT overlap with the TUN
	// interface address (198.18.0.1) or the in-tunnel DNS server (198.18.0.2),
	// avoiding the routing conflict that would result from a /16 pool starting
	// at 198.18.0.0.
	defaultMapDNSNetwork = "100.64.0.0"
	defaultMapDNSNetmask = "255.192.0.0"
)
