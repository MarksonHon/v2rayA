//go:build darwin
// +build darwin

package tun

import (
	"net/netip"

	"github.com/v2rayA/v2rayA/db/configure"
)

// platformPreExcludeAddrs on macOS returns addresses that should be excluded from TUN routing.
// macOS lacks fwmark, so direct DNS servers used by v2ray/xray must be excluded
// to prevent DNS traffic loops (TUN captures outbound DNS → v2ray/xray sends
// another DNS query → TUN captures again → infinite loop).
func platformPreExcludeAddrs() []netip.Prefix {
	var prefixes []netip.Prefix

	dnsRules := configure.GetDnsRulesNotNil()

	for _, rule := range dnsRules {
		if rule.Outbound == "direct" {
			dnsHosts := parseDNSServerHost(rule.Server)
			for _, host := range dnsHosts {
				ips := resolveDnsHost(host)
				for _, ip := range ips {
					prefix := netip.PrefixFrom(ip, ip.BitLen())
					prefixes = append(prefixes, prefix)
				}
			}
		}
	}

	return prefixes
}

// platformTunName 在 macOS 上返回空字符串。
//
// macOS 的 TUN 接口名必须以 "utun" 开头且由内核分配，
// sing-tun 收到空字符串时会自动选择 utun0、utun1 等可用名称。
func platformTunName() string {
	return "" // 由系统自动分配（utun0 / utun1 / …）
}

// platformDisableAutoRoute 在 macOS 上返回 false：
// sing-tun 在 macOS 上的 AutoRoute 工作正常，无需手动管理。
func platformDisableAutoRoute() bool {
	return false
}

// platformPostStart 在 macOS 上通过 networksetup 配置系统 DNS。
func platformPostStart(dnsServers []netip.Addr, tunName string, autoRoute bool) {
	if len(dnsServers) > 0 {
		if err := SetupTunDNS(dnsServers, tunName); err != nil {
			// 非致命，sing-tun 会在 TUN 层面拦截 DNS 查询
		}
	}
}

// platformPreClose 在 macOS 上恢复 DNS 配置。
func platformPreClose(tunName string, autoRoute bool) {
	CleanupTunDNS(tunName)
}
