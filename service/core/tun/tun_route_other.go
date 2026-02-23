//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package tun

func applyRoutes(opts RouteOptions) error { return nil }

func cleanupRoutes() error { return nil }
