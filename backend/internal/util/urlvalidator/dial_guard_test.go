package urlvalidator

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestM3_IsDisallowedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "100.127.255.254", "0.0.0.0", "0.1.2.3", "198.18.0.1", "198.19.255.255",
		"192.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255", "224.0.0.1",
		"::", "::1", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "2001:db8::1", "100::1", "64:ff9b:1::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:100.64.0.1",
	}
	for _, s := range blocked {
		require.Truef(t, IsDisallowedIP(net.ParseIP(s)), "%s should be blocked", s)
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "2606:4700:4700::1111"}
	for _, s := range allowed {
		require.Falsef(t, IsDisallowedIP(net.ParseIP(s)), "%s should be allowed", s)
	}
	require.True(t, IsDisallowedIP(nil))
	require.True(t, IsBlockedHost("100.64.1.1"), "literal CGNAT host is blocked too")
}

func TestM3_CheckDialAddress(t *testing.T) {
	require.NoError(t, CheckDialAddress("8.8.8.8:443"))
	require.NoError(t, CheckDialAddress("[2606:4700:4700::1111]:443"))
	for _, a := range []string{"127.0.0.1:80", "[::1]:80", "169.254.169.254:80", "100.64.0.1:443", "example.com:443"} {
		require.ErrorIsf(t, CheckDialAddress(a), ErrDialAddressNotAllowed, "%s", a)
	}
}

// 域名（localhost → 127.0.0.1）在拨号层被拒：Control 拿到的是解析后真正要连的 IP。
func TestM3_DialControlRejectsResolvedLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	d := &net.Dialer{Timeout: 2 * time.Second, Control: DialControl}
	_, err = d.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDialAddressNotAllowed), "got %v", err)

	// 未开启校验的 dialer 能正常连上（对照组）。
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	_ = conn.Close()
}

func TestM3_DialControlContextEnforceToggle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	type key struct{}
	d := &net.Dialer{Timeout: 2 * time.Second, ControlContext: DialControlContext(func(ctx context.Context) bool {
		return ctx.Value(key{}) != nil
	})}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	_ = conn.Close()

	_, err = d.DialContext(context.WithValue(context.Background(), key{}, true), "tcp", ln.Addr().String())
	require.ErrorIs(t, err, ErrDialAddressNotAllowed)
}
