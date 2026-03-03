//go:build linux
// +build linux

package tun

import (
	"net/netip"

	"github.com/v2rayA/v2rayA/common/cmds"
	"github.com/v2rayA/v2rayA/pkg/util/log"
)

const (
	// TUN_ROUTE_TABLE is the dedicated routing table for the TUN interface
	TUN_ROUTE_TABLE = 2026
	// FWMARK is the mark used by v2ray/xray outbound and plugin traffic
	FWMARK = 0x80
)

// SetupPreTunRouteRules installs fwmark-based policy routing rules BEFORE the
// TUN interface is created.  This is critical to avoid a race condition:
//
//	tun.New() activates sing-tun routing rules (pref 9000+) that redirect
//	public-IP traffic into the TUN interface.  If the fwmark bypass rule
//	(pref 100) is not yet present, v2ray/xray outbound packets (marked 0x80)
//	will also be captured → forwarded through SOCKS5 → back to v2ray →
//	infinite routing loop → v2ray becomes unresponsive → Observatory API
//	unreachable → "context deadline exceeded".
//
// By installing the fwmark rule first, marked traffic always uses the main
// table regardless of when sing-tun's rules appear.
func SetupPreTunRouteRules() error {
	commands := []string{
		// IPv4: make fwmark 0x80 traffic prioritize the main routing table
		"ip rule add fwmark 0x80 table main pref 100 2>/dev/null || true",
		// IPv6: same as above
		"ip -6 rule add fwmark 0x80 table main pref 100 2>/dev/null || true",
	}
	for _, cmd := range commands {
		if err := cmds.ExecCommands(cmd, false); err != nil {
			log.Warn("[TUN] SetupPreTunRouteRules: command execution failed '%s': %v", cmd, err)
		}
	}
	log.Info("[TUN] Linux fwmark bypass rules (pref 100) installed before TUN creation")
	return nil
}

// SetupTunRouteRules is a no-op on Linux.
// The fwmark policy routing rules are now installed early by SetupPreTunRouteRules
// to prevent the race condition between TUN route activation and fwmark bypass.
func SetupTunRouteRules() error {
	return nil
}

// CleanupTunRouteRules deletes the policy routing rules added by SetupTunRouteRules.
func CleanupTunRouteRules() error {
	commands := []string{
		"ip rule del fwmark 0x80 table main pref 100 2>/dev/null || true",
		"ip -6 rule del fwmark 0x80 table main pref 100 2>/dev/null || true",
	}
	for _, cmd := range commands {
		if err := cmds.ExecCommands(cmd, false); err != nil {
			log.Warn("[TUN] CleanupTunRouteRules: command execution failed '%s': %v", cmd, err)
		}
	}
	log.Info("[TUN] Linux policy routing rules cleared")
	return nil
}

// SetupExcludeRoutes is a no-operation on Linux.
// Linux implements exclusion through fwmark policy routing, so static routes are not needed.
func SetupExcludeRoutes(_ []netip.Prefix) error {
	return nil
}

// CleanupExcludeRoutes is a no-operation on Linux.
func CleanupExcludeRoutes() error {
	return nil
}

// SetupTunDNS is a no-operation on Linux.
// sing-tun already handles DNS through SystemdResolved or /etc/resolv.conf.
func SetupTunDNS(_ []netip.Addr, _ string) error {
	return nil
}

// CleanupTunDNS is a no-operation on Linux.
func CleanupTunDNS(_ string) error {
	return nil
}

// setTunRouteAutoMode is a no-operation on Linux.
// Linux handles routing via fwmark policy routes and does not need dynamic adjustments based on AutoRoute mode.
func setTunRouteAutoMode(_ bool) {}

// DynAddExcludeRoute is a no-operation on Linux.
// Linux bypasses TUN via fwmark (0x80) + policy routing tables and does not require additional host routes.
func DynAddExcludeRoute(_ netip.Addr) {}
