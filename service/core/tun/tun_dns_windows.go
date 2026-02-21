//go:build windows

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"

	"github.com/v2rayA/v2rayA/pkg/util/log"
)

// restoreInterfaceDNS sets DNS servers on the TUN interface via netsh.
// sing-tun always clears DNS when AutoRoute=false, so we set it back explicitly.
func restoreInterfaceDNS(ifName string, servers []netip.Addr) error {
	first4 := true
	first6 := true
	for _, addr := range servers {
		if addr.Is4() {
			var args []string
			if first4 {
				args = []string{"interface", "ipv4", "set", "dns",
					fmt.Sprintf("name=%s", ifName), "source=static",
					fmt.Sprintf("address=%s", addr.String()), "validate=no"}
				first4 = false
			} else {
				args = []string{"interface", "ipv4", "add", "dns",
					fmt.Sprintf("name=%s", ifName),
					fmt.Sprintf("address=%s", addr.String()), "validate=no"}
			}
			if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("netsh ipv4 dns %s: %w (output: %s)", addr, err, out)
			}
			log.Info("[TUN] Set interface IPv4 DNS: %s on %s", addr, ifName)
		} else {
			var args []string
			if first6 {
				args = []string{"interface", "ipv6", "set", "dns",
					fmt.Sprintf("name=%s", ifName), "source=static",
					fmt.Sprintf("address=%s", addr.String()), "validate=no"}
				first6 = false
			} else {
				args = []string{"interface", "ipv6", "add", "dns",
					fmt.Sprintf("name=%s", ifName),
					fmt.Sprintf("address=%s", addr.String()), "validate=no"}
			}
			if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("netsh ipv6 dns %s: %w (output: %s)", addr, err, out)
			}
			log.Info("[TUN] Set interface IPv6 DNS: %s on %s", addr, ifName)
		}
	}
	return nil
}
