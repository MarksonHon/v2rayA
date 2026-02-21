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
	case configure.TransparentGvisorTun, configure.TransparentSystemTun:
		mode, _, _ := strings.Cut(string(setting.TransparentType), "_")
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
		_, serverInfos, _ := getConnectedServerObjs()
		for _, info := range serverInfos {
			host := info.Info.GetHostname()
			if addr, err := netip.ParseAddr(host); err == nil {
				// Already an IP address — no DNS needed.
				tun.Default.AddIPWhitelist(addr)
			} else {
				// Domain name — resolve to IPs with retry.
				log.Info("[TUN] Resolving server domain: %s", host)
				var ips []net.IP
				var lookupErr error
				for attempt := 0; attempt < 3; attempt++ {
					if attempt > 0 {
						time.Sleep(300 * time.Millisecond)
						log.Info("[TUN] Retrying DNS for %s (attempt %d/3)", host, attempt+1)
					}
					ips, lookupErr = net.LookupIP(host)
					if lookupErr == nil {
						break
					}
				}
				// Always add domain to DNS whitelist (ensures real IP, not FakeIP, is returned).
				tun.Default.AddDomainWhitelist(host)
				if lookupErr == nil {
					log.Info("[TUN] Resolved %s to %d IP address(es)", host, len(ips))
					for _, ip := range ips {
						if addr, ok := netip.AddrFromSlice(ip); ok {
							tun.Default.AddIPWhitelist(addr)
						}
					}
				} else {
					// All retries failed. The server IP is unknown and cannot be excluded from
					// TUN routes. Traffic to the VPN server may loop back through TUN.
					// Log a clear warning so users can diagnose the issue.
					log.Warn("[TUN] Failed to resolve server domain %s after 3 attempts: %v", host, lookupErr)
					log.Warn("[TUN] Server IP is NOT excluded from TUN routes — routing loop is possible. Check your DNS.")
				}
			}
		}

		// Now start TUN with the exclusion list configured
		if err = tun.Default.Start(tun.Stack(mode)); err != nil {
			return fmt.Errorf("not support \"%s tun\" mode of transparent proxy: %w", mode, err)
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
