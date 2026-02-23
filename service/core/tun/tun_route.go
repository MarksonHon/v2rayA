package tun

import "net/netip"

// RouteOptions controls per-platform route setup for the TUN helper.
type RouteOptions struct {
	TunName string
	Exclude []netip.Prefix
}
