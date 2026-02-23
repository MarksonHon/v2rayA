package tun

import "net/netip"

type Stack string

const (
	StackGvisor = Stack("gvisor")
	StackSystem = Stack("system")
	StackHev    = Stack("hev")
)

type Tun interface {
	Start(stack Stack) error
	Close() error
	AddDomainWhitelist(domain string)
	AddIPWhitelist(addr netip.Addr)
	SetFakeIP(enabled bool)
	SetIPv6(enabled bool)
	SetStrictRoute(enabled bool)
	SetAutoRoute(enabled bool)
	SetPostScript(script string)
}

// Default is the global TUN runner (Hev-based)
var Default = NewHevTun()
