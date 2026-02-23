package tun

import (
	"net"
	"net/netip"

	"github.com/v2rayA/v2rayA/pkg/util/log"
)

// ResolveDnsServersToExcludes resolves host strings to IP prefixes for exclusion rules.
func ResolveDnsServersToExcludes(hosts []string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Warn("[TUN] ResolveDnsServersToExcludes: failed to resolve %s: %v", host, err)
			continue
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
	}
	return prefixes
}
