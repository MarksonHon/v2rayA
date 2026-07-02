//go:build !windows
// +build !windows

package v2ray

import "fmt"

// proxifyreSocksPort is the SOCKS5 port reserved for ProxiFyre traffic.
// Kept in the stub so that template_inbound.go can reference it unconditionally.
const proxifyreSocksPort = 52345

// IsProxifyreEnabled reports whether ProxiFyre support is available.
// On non-Windows platforms this is always false.
func IsProxifyreEnabled() bool { return false }

// GetProxifyreBinPath returns an error on non-Windows platforms.
func GetProxifyreBinPath() (string, error) {
	return "", fmt.Errorf("ProxiFyre is only supported on Windows")
}

// startProxifyre is a stub that returns an error when not on Windows.
func startProxifyre(_ *Template) error {
	return fmt.Errorf("ProxiFyre is only supported on Windows")
}

// stopProxifyre is a no-op stub when not on Windows.
func stopProxifyre() {}
