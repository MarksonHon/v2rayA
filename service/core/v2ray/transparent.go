package v2ray

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/v2rayA/v2rayA/conf"
	"github.com/v2rayA/v2rayA/core/iptables"
	"github.com/v2rayA/v2rayA/core/tun"
	"github.com/v2rayA/v2rayA/db/configure"
	"github.com/v2rayA/v2rayA/pkg/util/log"
)

func deleteTransparentProxyRules() {
	iptables.CloseWatcher()
	if !conf.GetEnvironmentConfig().Lite {
		removeResolvHijacker()
		iptables.Tproxy.GetCleanCommands().Run(false)
		iptables.Redirect.GetCleanCommands().Run(false)
		iptables.DropSpoofing.GetCleanCommands().Run(false)
		tun.Default.Close()
	}
	iptables.SystemProxy.GetCleanCommands().Run(false)
	time.Sleep(30 * time.Millisecond)
}

func writeTransparentProxyRules() (err error) {
	defer func() {
		if err != nil {
			log.Warn("writeTransparentProxyRules: %v", err)
			deleteTransparentProxyRules()
		}
	}()
	setting := configure.GetSettingNotNil()
	switch setting.TransparentType {
	case configure.TransparentTproxy:
		if err = iptables.Tproxy.GetSetupCommands().Run(true); err != nil {
			if strings.Contains(err.Error(), "TPROXY") && strings.Contains(err.Error(), "No chain") {
				err = fmt.Errorf("you does not compile xt_TPROXY in kernel")
			}
			return fmt.Errorf("not support \"tproxy\" mode of transparent proxy: %w", err)
		}
		iptables.SetWatcher(iptables.Tproxy)
	case configure.TransparentRedirect:
		if err = iptables.Redirect.GetSetupCommands().Run(true); err != nil {
			return fmt.Errorf("not support \"redirect\" mode of transparent proxy: %w", err)
		}
		iptables.SetWatcher(iptables.Redirect)
	case configure.TransparentHevTun:
		tun.Default.SetFakeIP(setting.TunFakeIP)
		tun.Default.SetIPv6(setting.TunIPv6)
		tun.Default.SetStrictRoute(setting.TunStrictRoute)
		tun.Default.SetAutoRoute(setting.TunAutoRoute)
		tun.Default.SetPostScript(setting.TunPostStartScript)

		// Extract and resolve DNS servers from v2ray configuration
		// Only direct-outbound DNS servers are excluded from TUN routing.
		// Proxy-bound DNS servers must remain inside TUN so their traffic is proxied correctly.
		log.Info("[TUN] Extracting direct DNS servers from configuration...")
		dnsHosts := ExtractDirectDnsServerHosts(setting)
		if len(dnsHosts) > 0 {
			dnsExcludes := tun.ResolveDnsServersToExcludes(dnsHosts)
			for _, prefix := range dnsExcludes {
				tun.Default.AddIPWhitelist(prefix.Addr())
				log.Info("[TUN] Added direct DNS server IP to exclusion list: %s", prefix.Addr())
			}
		}

		// Add server addresses to exclusion list BEFORE starting TUN.
		// For domain-name servers, resolve IPs so they can be excluded from TUN routes
		// (Inet4RouteExcludeAddress). Without exclusion, v2ray's outbound connections to the
		// VPN server would be captured by TUN and forwarded back to v2ray — an infinite loop.
		// Retry up to 3 times; transient DNS issues are common at startup on some platforms.
		nodeHosts := collectAllNodeHosts()
		_, connectedInfos, _ := getConnectedServerObjs()
		for _, info := range connectedInfos {
			host := info.Info.GetHostname()
			if host != "" {
				nodeHosts = append(nodeHosts, host)
			}
		}
		excludeSeen := make(map[string]struct{})
		for _, host := range nodeHosts {
			addHostExclusionToTun(host, excludeSeen)
		}

		// Now start TUN with the exclusion list configured
		if err = tun.Default.Start(tun.StackHev); err != nil {
			return fmt.Errorf("not support \"hev tun\" mode of transparent proxy: %w", err)
		}
	case configure.TransparentSystemProxy:
		if err = iptables.SystemProxy.GetSetupCommands().Run(true); err != nil {
			return fmt.Errorf("not support \"system proxy\" mode of transparent proxy: %w", err)
		}
	default:
		return fmt.Errorf("undefined \"%v\" mode of transparent proxy", setting.TransparentType)
	}

	if setting.Transparent != configure.TransparentClose &&
		setting.TransparentType == configure.TransparentRedirect &&
		!conf.GetEnvironmentConfig().Lite {
		resetResolvHijacker()
	}
	return nil
}

// collectAllNodeHosts gathers every known node hostname/IP from saved servers and subscriptions.
func collectAllNodeHosts() []string {
	hosts := make([]string, 0)
	for _, srv := range configure.GetServers() {
		if host := strings.TrimSpace(srv.ServerObj.GetHostname()); host != "" {
			hosts = append(hosts, host)
		}
	}
	for _, sub := range configure.GetSubscriptions() {
		for _, srv := range sub.Servers {
			if host := strings.TrimSpace(srv.ServerObj.GetHostname()); host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}

// addHostExclusionToTun resolves and excludes a single host (domain or IP) from the TUN path.
func addHostExclusionToTun(host string, seen map[string]struct{}) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	if seen != nil {
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		tun.Default.AddIPWhitelist(addr)
		return
	}
	// Domain — ensure it returns real IP (not FakeIP) and resolve to add explicit exclusions.
	tun.Default.AddDomainWhitelist(host)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
			log.Info("[TUN] Retrying DNS for %s (attempt %d/3)", host, attempt+1)
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				tun.Default.AddIPWhitelist(addr)
			}
		}
		return
	}
	if lastErr != nil {
		log.Warn("[TUN] Failed to resolve node %s for exclusion: %v", host, lastErr)
		log.Warn("[TUN] Node may loop through TUN; check DNS or add manual route.")
	}
}

func IsTransparentOn(setting *configure.Setting) bool {
	if setting == nil {
		setting = configure.GetSettingNotNil()
	}
	if setting.Transparent == configure.TransparentClose {
		return false
	}
	if conf.GetEnvironmentConfig().Lite &&
		(setting.TransparentType == configure.TransparentTproxy ||
			setting.TransparentType == configure.TransparentRedirect) {
		return false
	}
	return true
}
