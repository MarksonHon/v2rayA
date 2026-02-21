//go:build !windows

package tun

import "net/netip"

// restoreInterfaceDNS is a no-op on non-Windows platforms.
// sing-tun with AutoRoute=true handles DNS natively; on other systems
// the OS resolves DNS independently of the TUN interface configuration.
func restoreInterfaceDNS(_ string, _ []netip.Addr) error {
	return nil
}
