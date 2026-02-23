//go:build linux
// +build linux

package tun

import (
	"fmt"

	"github.com/v2rayA/v2rayA/common/cmds"
	"github.com/v2rayA/v2rayA/pkg/util/log"
)

func applyRoutes(opts RouteOptions) error {
	commands := []string{
		"sysctl -w net.ipv4.conf.all.rp_filter=0",
		fmt.Sprintf("sysctl -w net.ipv4.conf.%s.rp_filter=0", opts.TunName),
		fmt.Sprintf("ip rule add fwmark 0x%x table main pref 10 2>/dev/null || true", defaultMark),
		fmt.Sprintf("ip -6 rule add fwmark 0x%x table main pref 10 2>/dev/null || true", defaultMark),
		fmt.Sprintf("ip route add default dev %s table 20 2>/dev/null || true", opts.TunName),
		"ip rule add lookup 20 pref 20 2>/dev/null || true",
		fmt.Sprintf("ip -6 route add default dev %s table 20 2>/dev/null || true", opts.TunName),
		"ip -6 rule add lookup 20 pref 20 2>/dev/null || true",
	}
	for _, prefix := range opts.Exclude {
		commands = append(commands,
			fmt.Sprintf("ip rule add to %s lookup main pref 5 2>/dev/null || true", prefix.String()),
			fmt.Sprintf("ip -6 rule add to %s lookup main pref 5 2>/dev/null || true", prefix.String()),
		)
	}
	for _, cmd := range commands {
		if err := cmds.ExecCommands(cmd, false); err != nil {
			log.Warn("applyRoutes: failed '%s': %v", cmd, err)
		}
	}
	return nil
}

func cleanupRoutes() error {
	commands := []string{
		fmt.Sprintf("ip rule del fwmark 0x%x table main pref 10 2>/dev/null || true", defaultMark),
		fmt.Sprintf("ip -6 rule del fwmark 0x%x table main pref 10 2>/dev/null || true", defaultMark),
		"ip rule del lookup 20 pref 20 2>/dev/null || true",
		"ip -6 rule del lookup 20 pref 20 2>/dev/null || true",
	}
	for _, cmd := range commands {
		if err := cmds.ExecCommands(cmd, false); err != nil {
			log.Warn("cleanupRoutes: failed '%s': %v", cmd, err)
		}
	}
	return nil
}
