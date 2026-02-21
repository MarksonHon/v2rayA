package tun

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// lingerDialer wraps a N.Dialer and sets SO_LINGER=0 on every new TCP connection
// to loopback addresses. This prevents TIME_WAIT accumulation on Windows when
// making many short-lived connections to a local proxy (e.g. 127.0.0.1:52345).
//
// Background: Windows keeps TCP connections in TIME_WAIT for ~4 minutes after
// close. With TUN mode proxying all traffic through a local SOCKS5 endpoint,
// each request creates a new TCP connection from 127.0.0.1:<ephemeral> to
// 127.0.0.1:52345. The ephemeral port range (~16384 ports) exhausts quickly,
// causing ConnectEx to return WSAEADDRINUSE.
//
// SetLinger(0) causes the TCP stack to send RST instead of FIN on close,
// skipping TIME_WAIT entirely and immediately reclaiming the ephemeral port.
// This is safe for loopback connections because TIME_WAIT exists to absorb
// delayed packets from remote hosts — a scenario impossible on loopback.
type lingerDialer struct {
	inner N.Dialer
}

// NewLingerDialer returns a N.Dialer that sets SO_LINGER=0 on TCP connections
// to loopback destinations, preventing TIME_WAIT port exhaustion on Windows.
func NewLingerDialer(inner N.Dialer) N.Dialer {
	return &lingerDialer{inner: inner}
}

func (d *lingerDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	conn, err := d.inner.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	// Only apply to TCP connections targeting loopback, where TIME_WAIT is
	// never useful but can exhaust ephemeral ports on Windows.
	if N.NetworkName(network) == N.NetworkTCP && address.Addr.IsLoopback() {
		if tc, ok := conn.(*net.TCPConn); ok {
			// Linger=0: close sends RST, skipping TIME_WAIT.
			_ = tc.SetLinger(0)
		}
	}
	return conn, nil
}

func (d *lingerDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.inner.ListenPacket(ctx, destination)
}
