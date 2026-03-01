//go:build windows
// +build windows

package tun

import "net/netip"

// platformPreExcludeAddrs 在 Windows 上预排除常用公网 DNS 服务器地址。
//
// Windows 没有 fwmark 机制，如果 v2ray/xray 核心向这些 DNS 发送直连请求，
// 而 TUN 恰好将这些目标地址的流量也劫持，就会导致路由回环。
// 预排除后，这些地址的流量会走物理网卡直接出去。
func platformPreExcludeAddrs() []netip.Prefix {
	var prefixes []netip.Prefix
	wellKnownDNS := []string{
		// Cloudflare
		"1.1.1.1/32", "1.0.0.1/32",
		// Google
		"8.8.8.8/32", "8.8.4.4/32",
		// Quad9
		"9.9.9.9/32", "149.112.112.112/32",
		// OpenDNS
		"208.67.222.222/32", "208.67.220.220/32",
		// 国内常用
		"114.114.114.114/32",
		"223.5.5.5/32", "223.6.6.6/32",
		// IPv6 Google
		"2001:4860:4860::8888/128", "2001:4860:4860::8844/128",
		// IPv6 Cloudflare
		"2606:4700:4700::1111/128", "2606:4700:4700::1001/128",
	}
	for _, cidr := range wellKnownDNS {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

// platformTunName 在 Windows 上返回自定义 TUN 接口名称。
func platformTunName() string {
	return "v2raya-tun"
}

// platformDisableAutoRoute 在 Windows 上返回 false。
//
// sing-tun v0.8.0+ 在 Windows 上通过 winipcfg LUID API 和 FWPM (StrictRoute) 实现
// 可靠的路由管理，无需手动管理。
func platformDisableAutoRoute() bool {
	return false
}

// platformPostStart 在 TUN 启动后为接口配置 DNS 服务器。
//
// 当 AutoRoute 启用时，sing-tun 已通过 luid.SetDNS() 处理 DNS，无需手动配置。
// 当 AutoRoute 关闭时（用户显式禁用），手动调用 SetupTunDNS。
func platformPostStart(dnsServers []netip.Addr, tunName string, autoRoute bool) {
	if autoRoute {
		// sing-tun 通过 winipcfg luid.SetDNS() 自动设置 DNS
		return
	}
	if len(dnsServers) > 0 {
		if err := SetupTunDNS(dnsServers, tunName); err != nil {
			// 非致命错误：DNS 设置失败不影响流量转发
		}
	}
}

// platformPreClose 在 TUN 关闭前清理 Windows 特有资源。
// AutoRoute 启用时 sing-tun 自行清理，无需手动操作。
func platformPreClose(tunName string, autoRoute bool) {
	if autoRoute {
		return
	}
	if tunName != "" {
		CleanupTunDNS(tunName)
	}
}
