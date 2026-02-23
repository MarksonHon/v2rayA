//go:build windows
// +build windows

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/v2rayA/v2rayA/pkg/util/log"
)

var (
	excludedRoutes  []netip.Prefix
	defaultGateway4 string
	defaultGateway6 string
	defaultIfIndex4 string
	defaultIfIndex6 string
	// savedTunMetric holds the interface metric before we override it with 1.
	savedTunMetric string
)

func applyRoutes(opts RouteOptions) error {
	gw4, if4, err := getDefaultGatewayAndIfIndex(false)
	if err != nil {
		log.Warn("applyRoutes: get IPv4 gateway failed: %v", err)
	}
	gw6, if6, err6 := getDefaultGatewayAndIfIndex(true)
	if err6 != nil {
		log.Warn("applyRoutes: get IPv6 gateway failed: %v", err6)
	}
	defaultGateway4, defaultGateway6 = gw4, gw6
	defaultIfIndex4, defaultIfIndex6 = if4, if6

	// Add per-IP bypass routes for excluded hosts BEFORE redirecting default
	// traffic into the TUN.  These use metric 1 so they always win over the
	// future TUN default route.
	excludedRoutes = opts.Exclude
	for _, prefix := range opts.Exclude {
		addr := prefix.Addr()
		var cmd *exec.Cmd
		if addr.Is4() && gw4 != "" {
			mask := netmaskFromPrefix(prefix)
			cmd = exec.Command("route", "add", addr.String(), "mask", mask, gw4, "metric", "1")
		} else if addr.Is6() && gw6 != "" {
			cmd = exec.Command("netsh", "interface", "ipv6", "add", "route", prefix.String(), "nexthop="+gw6, "metric=1")
		} else {
			continue
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warn("applyRoutes: failed to add route %s: %v (output: %s)", prefix.String(), err, strings.TrimSpace(string(out)))
		}
	}

	// WinTun adapter creation is asynchronous; retry until the interface appears
	// (typically within 1–3 s) before attempting to configure it.
	tunIdx, err := waitForInterfaceIndex(opts.TunName, 10*time.Second)
	if err != nil {
		log.Warn("applyRoutes: TUN interface %s not ready after timeout, skipping default route: %v", opts.TunName, err)
		return nil
	}

	// ── Step 1: set interface metric to 1 ────────────────────────────────────
	// Windows selects the outbound interface by (interface metric + route metric).
	// Setting the TUN interface metric to 1 guarantees it beats every physical
	// adapter (which typically have metric 25–50).
	//
	// Save the old metric so we can restore it on cleanup.
	if m, e := getInterfaceMetric(tunIdx); e == nil {
		savedTunMetric = m
	}
	if out, e := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Set-NetIPInterface -InterfaceIndex %s -InterfaceMetric 1", tunIdx),
	).CombinedOutput(); e != nil {
		log.Warn("applyRoutes: Set-NetIPInterface metric failed (if=%s): %v (output: %s)", tunIdx, e, strings.TrimSpace(string(out)))
	}

	// ── Step 2: add explicit default routes pointing at TUN ──────────────────
	// Use New-NetRoute (PowerShell) which is idempotent-safe via -ErrorAction.
	// NextHop 0.0.0.0 means "on-link" for IPv4 through a point-to-point TUN.
	addRoute4PS := fmt.Sprintf(
		`$e = $null
		New-NetRoute -InterfaceIndex %s -DestinationPrefix '0.0.0.0/0' -NextHop '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable e
		if ($e) { Set-NetRoute -InterfaceIndex %s -DestinationPrefix '0.0.0.0/0' -NextHop '%s' -RouteMetric 1 -ErrorAction SilentlyContinue }`,
		tunIdx, defaultIPv4, tunIdx, defaultIPv4,
	)
	if out, e := exec.Command("powershell", "-NoProfile", "-Command", addRoute4PS).CombinedOutput(); e != nil {
		log.Warn("applyRoutes: failed to add default IPv4 route to TUN (if=%s): %v (output: %s)", tunIdx, e, strings.TrimSpace(string(out)))
	}

	// IPv6 default route via TUN (only when IPv6 is likely present)
	if defaultGateway6 != "" || defaultIPv6 != "" {
		addRoute6PS := fmt.Sprintf(
			`$e = $null
			New-NetRoute -InterfaceIndex %s -DestinationPrefix '::/0' -NextHop '::' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable e
			if ($e) { Set-NetRoute -InterfaceIndex %s -DestinationPrefix '::/0' -NextHop '::' -RouteMetric 1 -ErrorAction SilentlyContinue }`,
			tunIdx, tunIdx,
		)
		if out, e := exec.Command("powershell", "-NoProfile", "-Command", addRoute6PS).CombinedOutput(); e != nil {
			log.Warn("applyRoutes: failed to add default IPv6 route to TUN (if=%s): %v (output: %s)", tunIdx, e, strings.TrimSpace(string(out)))
		}
	}

	// ── Step 3: point Windows DNS at the TUN MapDNS server ───────────────────
	// Even with the default route through TUN, Windows DNS Client sometimes
	// bypasses TUN for DNS resolution (it selects interfaces independently of
	// the routing table).  Setting the TUN adapter's DNS server address to the
	// hev MapDNS listener (198.18.0.2) forces all DNS queries to flow through
	// the TUN, where hev intercepts them and returns FakeIPs.
	setDNSPS := fmt.Sprintf(
		"Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses '%s'",
		tunIdx, defaultMapDNS,
	)
	if out, e := exec.Command("powershell", "-NoProfile", "-Command", setDNSPS).CombinedOutput(); e != nil {
		log.Warn("applyRoutes: failed to set TUN DNS server (if=%s): %v (output: %s)", tunIdx, e, strings.TrimSpace(string(out)))
	}

	return nil
}

// waitForInterfaceIndex polls getInterfaceIndex until the WinTun adapter has
// appeared in the NDIS stack or the timeout elapses.
func waitForInterfaceIndex(name string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		idx, err := getInterfaceIndex(name)
		if err == nil {
			return idx, nil
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	return "", fmt.Errorf("interface %q not ready within %v: %w", name, timeout, lastErr)
}

func cleanupRoutes() error {
	tunIdx, err := getInterfaceIndex(defaultTunName)
	if err == nil {
		// Restore original interface metric
		if savedTunMetric != "" {
			if out, e := exec.Command("powershell", "-NoProfile", "-Command",
				fmt.Sprintf("Set-NetIPInterface -InterfaceIndex %s -InterfaceMetric %s", tunIdx, savedTunMetric),
			).CombinedOutput(); e != nil {
				log.Warn("cleanupRoutes: failed to restore TUN interface metric: %v (output: %s)", e, strings.TrimSpace(string(out)))
			}
		}
		// Remove the default routes we added
		rmPS := fmt.Sprintf(
			`Remove-NetRoute -InterfaceIndex %s -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
			 Remove-NetRoute -InterfaceIndex %s -DestinationPrefix '::/0'     -Confirm:$false -ErrorAction SilentlyContinue`,
			tunIdx, tunIdx,
		)
		if out, e := exec.Command("powershell", "-NoProfile", "-Command", rmPS).CombinedOutput(); e != nil {
			log.Warn("cleanupRoutes: failed to remove TUN default routes: %v (output: %s)", e, strings.TrimSpace(string(out)))
		}
		// Restore DNS server to automatic (DHCP-assigned)
		restoreDNSPS := fmt.Sprintf(
			"Set-DnsClientServerAddress -InterfaceIndex %s -ResetServerAddresses", tunIdx,
		)
		if out, e := exec.Command("powershell", "-NoProfile", "-Command", restoreDNSPS).CombinedOutput(); e != nil {
			log.Warn("cleanupRoutes: failed to reset TUN DNS server: %v (output: %s)", e, strings.TrimSpace(string(out)))
		}
	}

	// Restore original default gateway on the physical interface
	if defaultGateway4 != "" && defaultIfIndex4 != "" {
		restorePS := fmt.Sprintf(
			`$e = $null
			New-NetRoute -InterfaceIndex %s -DestinationPrefix '0.0.0.0/0' -NextHop '%s' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable e
			if ($e) { Set-NetRoute -InterfaceIndex %s -DestinationPrefix '0.0.0.0/0' -NextHop '%s' -RouteMetric 0 -ErrorAction SilentlyContinue }`,
			defaultIfIndex4, defaultGateway4, defaultIfIndex4, defaultGateway4,
		)
		if out, e := exec.Command("powershell", "-NoProfile", "-Command", restorePS).CombinedOutput(); e != nil {
			log.Warn("cleanupRoutes: failed to restore default IPv4 route: %v (output: %s)", e, strings.TrimSpace(string(out)))
		}
	}
	if defaultGateway6 != "" && defaultIfIndex6 != "" {
		restorePS6 := fmt.Sprintf(
			`$e = $null
			New-NetRoute -InterfaceIndex %s -DestinationPrefix '::/0' -NextHop '%s' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable e
			if ($e) { Set-NetRoute -InterfaceIndex %s -DestinationPrefix '::/0' -NextHop '%s' -RouteMetric 0 -ErrorAction SilentlyContinue }`,
			defaultIfIndex6, defaultGateway6, defaultIfIndex6, defaultGateway6,
		)
		if out, e := exec.Command("powershell", "-NoProfile", "-Command", restorePS6).CombinedOutput(); e != nil {
			log.Warn("cleanupRoutes: failed to restore default IPv6 route: %v (output: %s)", e, strings.TrimSpace(string(out)))
		}
	}

	for _, prefix := range excludedRoutes {
		addr := prefix.Addr()
		var cmd *exec.Cmd
		if addr.Is4() {
			cmd = exec.Command("route", "delete", addr.String())
		} else {
			cmd = exec.Command("netsh", "interface", "ipv6", "delete", "route", prefix.String())
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warn("cleanupRoutes: failed to delete route %s: %v (output: %s)", prefix.String(), err, strings.TrimSpace(string(out)))
		}
	}
	excludedRoutes = nil
	defaultGateway4, defaultGateway6 = "", ""
	defaultIfIndex4, defaultIfIndex6 = "", ""
	savedTunMetric = ""
	return nil
}

func getDefaultGatewayAndIfIndex(ipv6 bool) (string, string, error) {
	var cmd *exec.Cmd
	if ipv6 {
		cmd = exec.Command("powershell", "-NoProfile", "-Command",
			"$r=Get-NetRoute -DestinationPrefix '::/0' | Sort-Object InterfaceMetric | Select-Object -First 1; if($r){$r.NextHop+';'+$r.InterfaceIndex}")
	} else {
		cmd = exec.Command("powershell", "-NoProfile", "-Command",
			"$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object InterfaceMetric | Select-Object -First 1; if($r){$r.NextHop+';'+$r.InterfaceIndex}")
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("get gateway: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}
	parts := strings.Split(strings.TrimSpace(string(output)), ";")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("unexpected gateway output: %s", strings.TrimSpace(string(output)))
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("empty gateway or ifIndex")
	}
	return parts[0], parts[1], nil
}

func getInterfaceIndex(name string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s' | Select-Object -First 1).ifIndex", name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get interface index: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}
	idx := strings.TrimSpace(string(output))
	if idx == "" {
		return "", fmt.Errorf("empty interface index")
	}
	return idx, nil
}

func getInterfaceMetric(ifIndex string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-NetIPInterface -InterfaceIndex %s -AddressFamily IPv4 | Select-Object -First 1).InterfaceMetric", ifIndex))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get interface metric: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}
	m := strings.TrimSpace(string(output))
	if m == "" {
		return "", fmt.Errorf("empty interface metric")
	}
	return m, nil
}

func netmaskFromPrefix(prefix netip.Prefix) string {
	bits := prefix.Bits()
	switch bits {
	case 32:
		return "255.255.255.255"
	case 31:
		return "255.255.255.254"
	case 30:
		return "255.255.255.252"
	case 29:
		return "255.255.255.248"
	case 28:
		return "255.255.255.240"
	case 27:
		return "255.255.255.224"
	case 26:
		return "255.255.255.192"
	case 25:
		return "255.255.255.128"
	case 24:
		return "255.255.255.0"
	case 16:
		return "255.255.0.0"
	case 8:
		return "255.0.0.0"
	default:
		mask := ^uint32(0) << (32 - bits)
		return fmt.Sprintf("%d.%d.%d.%d", byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
	}
}
