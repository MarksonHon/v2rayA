//go:build darwin
// +build darwin

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/v2rayA/v2rayA/pkg/util/log"
)

var (
	darwinExcluded []netip.Prefix
	darwinGateway4 string
	darwinGateway6 string
)

func applyRoutes(opts RouteOptions) error {
	gw4, err4 := getDarwinGateway()
	if err4 != nil {
		log.Warn("applyRoutes: get IPv4 gateway failed: %v", err4)
	}
	gw6, err6 := getDarwinGateway6()
	if err6 != nil {
		log.Warn("applyRoutes: get IPv6 gateway failed: %v", err6)
	}
	darwinGateway4, darwinGateway6 = gw4, gw6

	darwinExcluded = opts.Exclude
	for _, prefix := range opts.Exclude {
		addr := prefix.Addr()
		var cmd *exec.Cmd
		if addr.Is4() && gw4 != "" {
			cmd = exec.Command("route", "add", addr.String(), gw4)
		} else if addr.Is6() && gw6 != "" {
			cmd = exec.Command("route", "add", "-inet6", addr.String(), gw6)
		} else {
			continue
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warn("applyRoutes: failed to add route %s: %v (output: %s)", prefix.String(), err, strings.TrimSpace(string(out)))
		}
	}

	if err := exec.Command("route", "change", "-inet", "default", "-interface", opts.TunName).Run(); err != nil {
		log.Warn("applyRoutes: failed to change default ipv4 route to %s: %v", opts.TunName, err)
	}
	if err := exec.Command("route", "change", "-inet6", "default", "-interface", opts.TunName).Run(); err != nil {
		log.Warn("applyRoutes: failed to change default ipv6 route to %s: %v", opts.TunName, err)
	}
	return nil
}

func cleanupRoutes() error {
	if darwinGateway4 != "" {
		if err := exec.Command("route", "change", "-inet", "default", darwinGateway4).Run(); err != nil {
			log.Warn("cleanupRoutes: failed to restore default ipv4 route: %v", err)
		}
	}
	if darwinGateway6 != "" {
		if err := exec.Command("route", "change", "-inet6", "default", darwinGateway6).Run(); err != nil {
			log.Warn("cleanupRoutes: failed to restore default ipv6 route: %v", err)
		}
	}

	for _, prefix := range darwinExcluded {
		addr := prefix.Addr()
		var cmd *exec.Cmd
		if addr.Is4() {
			cmd = exec.Command("route", "delete", addr.String())
		} else {
			cmd = exec.Command("route", "delete", "-inet6", addr.String())
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warn("cleanupRoutes: failed to delete route %s: %v (output: %s)", prefix.String(), err, strings.TrimSpace(string(out)))
		}
	}
	darwinExcluded = nil
	darwinGateway4 = ""
	darwinGateway6 = ""
	return nil
}

func getDarwinGateway() (string, error) {
	cmd := exec.Command("sh", "-c", "route -n get default | awk '/gateway/ {print $2}'")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get gateway: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}
	gateway := strings.TrimSpace(string(output))
	if gateway == "" {
		return "", fmt.Errorf("empty gateway")
	}
	return gateway, nil
}

func getDarwinGateway6() (string, error) {
	cmd := exec.Command("sh", "-c", "route -n get -inet6 default | awk '/gateway/ {print $2}'")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get ipv6 gateway: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}
	gw := strings.TrimSpace(string(output))
	if gw == "" {
		return "", fmt.Errorf("empty ipv6 gateway")
	}
	return gw, nil
}
