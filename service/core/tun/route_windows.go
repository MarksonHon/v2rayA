//go:build windows
// +build windows

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/v2rayA/v2rayA/pkg/util/log"
)

// Windows TUN 网关 IP（sing-tun 固定分配的地址）
const tunGateway4 = "172.19.0.2"

var (
	// 记录各类路由是否已添加，用于精确清理
	excludedRoutes       []netip.Prefix
	tunDefaultRouteAdded bool
	loopbackRouteAdded   bool
)

// SetupTunRouteRules 在 Windows 上手动建立 TUN 默认路由。
//
// sing-tun 的 AutoRoute 在 Windows 上存在可靠性问题，
// 因此关闭 AutoRoute 并手动添加以下路由：
//
//   - 127.0.0.0/8 → 127.0.0.1  metric 0   （保证回环流量不经 TUN）
//   - 0.0.0.0/0   → 172.19.0.2 metric 1   （全局流量走 TUN，低于物理接口 metric）
func SetupTunRouteRules() error {
	// --- IPv4 回环路由 ---
	loopbackArgs := []string{"add", "127.0.0.0", "mask", "255.0.0.0", "127.0.0.1", "metric", "0"}
	out, err := exec.Command("route", loopbackArgs...).CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "对象已存在") || strings.Contains(s, "already exists") {
			log.Info("[TUN][Windows] 回环路由 127.0.0.0/8 已存在")
		} else {
			log.Warn("[TUN][Windows] 添加回环路由失败: %v, output: %s", err, s)
		}
	} else {
		loopbackRouteAdded = true
		log.Info("[TUN][Windows] 添加回环路由 127.0.0.0/8 → 127.0.0.1 metric 0")
	}

	// --- IPv4 默认路由经 TUN ---
	defaultArgs := []string{"add", "0.0.0.0", "mask", "0.0.0.0", tunGateway4, "metric", "1"}
	out, err = exec.Command("route", defaultArgs...).CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "对象已存在") || strings.Contains(s, "already exists") {
			log.Info("[TUN][Windows] 默认路由 0.0.0.0/0 → %s 已存在", tunGateway4)
			tunDefaultRouteAdded = true
		} else {
			log.Warn("[TUN][Windows] 添加默认路由失败: %v, output: %s", err, s)
			return err
		}
	} else {
		tunDefaultRouteAdded = true
		log.Info("[TUN][Windows] 添加默认路由 0.0.0.0/0 → %s metric 1", tunGateway4)
	}
	return nil
}

// CleanupTunRouteRules 删除 SetupTunRouteRules 添加的路由条目。
func CleanupTunRouteRules() error {
	if loopbackRouteAdded {
		out, err := exec.Command("route", "delete", "127.0.0.0", "mask", "255.0.0.0").CombinedOutput()
		if err != nil {
			log.Warn("[TUN][Windows] 删除回环路由失败: %v, output: %s", err, string(out))
		} else {
			log.Info("[TUN][Windows] 已删除回环路由 127.0.0.0/8")
		}
		loopbackRouteAdded = false
	}

	if tunDefaultRouteAdded {
		// 指定 nexthop 只删除 TUN 那条默认路由，不影响物理接口
		out, err := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", tunGateway4).CombinedOutput()
		if err != nil {
			log.Warn("[TUN][Windows] 删除 TUN 默认路由失败: %v, output: %s", err, string(out))
		} else {
			log.Info("[TUN][Windows] 已删除默认路由 → %s", tunGateway4)
		}
		tunDefaultRouteAdded = false
	}
	return nil
}

// SetupExcludeRoutes 为服务端 IP 添加"绕过 TUN"的静态路由。
//
// Windows 没有 fwmark 机制，需要在 TUN 默认路由之前显式为每个
// 代理服务端 IP 添加经过物理网关的路由，防止流量回环。
func SetupExcludeRoutes(addrs []netip.Prefix) error {
	if len(addrs) == 0 {
		return nil
	}
	excludedRoutes = addrs

	gw, err := getDefaultGateway()
	if err != nil {
		log.Warn("[TUN][Windows] 获取默认网关失败: %v", err)
		return err
	}

	for _, prefix := range addrs {
		addr := prefix.Addr()
		if addr.Is4() {
			mask := netmaskFromPrefix(prefix)
			// metric 5：高于 TUN 默认路由(1)，低于一般主机路由(25+)，确保这些 IP 直连
			out, err := exec.Command("route", "add", addr.String(), "mask", mask, gw, "metric", "5").CombinedOutput()
			if err != nil {
				s := string(out)
				if !strings.Contains(s, "对象已存在") && !strings.Contains(s, "already exists") {
					log.Warn("[TUN][Windows] 添加排除路由 %s 失败: %v, output: %s", addr, err, s)
				}
			} else {
				log.Info("[TUN][Windows] 添加排除路由 %s/mask %s → %s metric 5", addr, mask, gw)
			}
		} else {
			// IPv6 排除路由使用 netsh
			out, err := exec.Command("netsh", "interface", "ipv6", "add", "route",
				prefix.String(), "nexthop="+gw, "metric=5").CombinedOutput()
			if err != nil {
				s := string(out)
				if !strings.Contains(s, "对象已存在") && !strings.Contains(s, "Element already exists") {
					log.Warn("[TUN][Windows] 添加 IPv6 排除路由 %s 失败: %v, output: %s", prefix, err, s)
				}
			} else {
				log.Info("[TUN][Windows] 添加 IPv6 排除路由 %s → %s metric 5", prefix, gw)
			}
		}
	}
	return nil
}

// CleanupExcludeRoutes 删除 SetupExcludeRoutes 添加的所有静态路由。
func CleanupExcludeRoutes() error {
	for _, prefix := range excludedRoutes {
		addr := prefix.Addr()
		if addr.Is4() {
			out, err := exec.Command("route", "delete", addr.String()).CombinedOutput()
			if err != nil {
				log.Warn("[TUN][Windows] 删除排除路由 %s 失败: %v, output: %s", addr, err, string(out))
			}
		} else {
			out, err := exec.Command("netsh", "interface", "ipv6", "delete", "route", prefix.String()).CombinedOutput()
			if err != nil {
				log.Warn("[TUN][Windows] 删除 IPv6 排除路由 %s 失败: %v, output: %s", prefix, err, string(out))
			}
		}
	}
	excludedRoutes = nil
	return nil
}

// SetupTunDNS 通过 PowerShell 为 TUN 接口设置 DNS 服务器地址。
//
// sing-tun 在 Windows 上无法自动将 TUN 接口的 DNS 配置推送到系统，
// 需要通过 Set-DnsClientServerAddress 手动完成。
func SetupTunDNS(dnsServers []netip.Addr, tunName string) error {
	if len(dnsServers) == 0 {
		return nil
	}

	ifName, err := getTunInterfaceName(tunName)
	if err != nil {
		log.Warn("[TUN][Windows] SetupTunDNS: 获取接口名失败: %v", err)
		return err
	}

	var v4, v6 []string
	for _, dns := range dnsServers {
		if dns.Is4() {
			v4 = append(v4, dns.String())
		} else {
			v6 = append(v6, dns.String())
		}
	}

	if len(v4) > 0 {
		list := strings.Join(v4, ",")
		psCmd := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @(%s)",
			ifName, "'"+strings.Join(v4, "','")+"'")
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
		if err != nil {
			log.Warn("[TUN][Windows] 设置 IPv4 DNS 失败: %v, output: %s", err, string(out))
			return err
		}
		log.Info("[TUN][Windows] 接口 '%s' IPv4 DNS 已设置: %s", ifName, list)
	}

	if len(v6) > 0 {
		list := strings.Join(v6, ",")
		psCmd := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @(%s)",
			ifName, "'"+strings.Join(v6, "','")+"'")
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
		if err != nil {
			log.Warn("[TUN][Windows] 设置 IPv6 DNS 失败: %v, output: %s", err, string(out))
		}
		log.Info("[TUN][Windows] 接口 '%s' IPv6 DNS 已设置: %s", ifName, list)
	}
	return nil
}

// CleanupTunDNS 将 TUN 接口的 DNS 恢复为 DHCP 自动获取。
func CleanupTunDNS(tunName string) error {
	ifName, err := getTunInterfaceName(tunName)
	if err != nil {
		// 接口可能已被删除，不视为错误
		return nil
	}
	psCmd := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses", ifName)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil {
		log.Warn("[TUN][Windows] 重置接口 DNS 失败: %v, output: %s", err, string(out))
	} else {
		log.Info("[TUN][Windows] 接口 '%s' DNS 已重置为自动获取", ifName)
	}
	return nil
}

// getDefaultGateway 获取当前系统物理接口的默认 IPv4 网关。
//
// 通过 PowerShell Get-NetRoute 筛选非 TUN 网关（排除 172.19.0.2 和 0.0.0.0），
// 按 InterfaceMetric 升序取第一条作为物理网关。
func getDefaultGateway() (string, error) {
	psCmd := `(Get-NetRoute -DestinationPrefix '0.0.0.0/0' |` +
		` Where-Object { $_.NextHop -ne '` + tunGateway4 + `' -and $_.NextHop -ne '0.0.0.0' } |` +
		` Sort-Object InterfaceMetric |` +
		` Select-Object -First 1).NextHop`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("获取默认网关失败: %w, output: %s", err, string(out))
	}
	gw := strings.TrimSpace(string(out))
	if gw == "" {
		return "", fmt.Errorf("默认网关为空（可能无网络连接）")
	}
	return gw, nil
}

// getTunInterfaceName 在 Windows 上通过 Get-NetAdapter 找到 TUN 接口的完整名称。
func getTunInterfaceName(baseName string) (string, error) {
	psCmd := fmt.Sprintf(
		"(Get-NetAdapter | Where-Object { $_.Name -like '*%s*' -and $_.Status -ne 'Not Present' } | Select-Object -First 1).Name",
		baseName)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("查找接口失败: %w, output: %s", err, string(out))
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return "", fmt.Errorf("未找到匹配接口: %s", baseName)
	}
	return name, nil
}

// netmaskFromPrefix 将前缀长度转换为点分十进制掩码字符串（仅 IPv4）。
func netmaskFromPrefix(prefix netip.Prefix) string {
	bits := prefix.Bits()
	mask := ^uint32(0) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
}
