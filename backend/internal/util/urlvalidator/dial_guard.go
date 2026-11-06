package urlvalidator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// M-3（第二轮）：出站请求的私网/保留地址判断统一走 IsDisallowedIP，并在拨号层（net.Dialer.ControlContext）
// 校验真正要连接的 IP，消除“校验时解析一次、连接时再解析一次”之间的 DNS rebinding 窗口。

// ErrDialAddressNotAllowed 表示拨号目标 IP 落在禁止网段。
var ErrDialAddressNotAllowed = errors.New("dial address is not allowed")

// reservedCIDRs 是 net.IP 内置判断（loopback/private/link-local/unspecified/multicast）之外补充的保留网段。
var reservedCIDRs = mustParseCIDRs(
	"0.0.0.0/8",       // “本网络”（RFC 1122），Linux 上 0.x 可能被当作本机
	"100.64.0.0/10",   // 运营商级 NAT（RFC 6598），常见于云厂商内网
	"192.0.0.0/24",    // IETF 协议分配（RFC 6890）
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // 基准测试网段（RFC 2544）
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // 保留（含 255.255.255.255 广播）
	"100::/64",        // IPv6 丢弃前缀（RFC 6666）
	"2001:db8::/32",   // IPv6 文档前缀
	"64:ff9b:1::/48",  // IPv6 本地 NAT64（RFC 8215）
	"fec0::/10",       // 已废弃的 IPv6 site-local
)

func mustParseCIDRs(values ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(values))
	for _, v := range values {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			panic(fmt.Sprintf("urlvalidator: bad cidr %q: %v", v, err))
		}
		out = append(out, n)
	}
	return out
}

// IsDisallowedIP 报告 ip 是否属于出站请求禁止访问的地址：回环、RFC1918/ULA 私网、链路本地、未指定、
// 组播，以及 reservedCIDRs 中的保留网段（100.64/10、0/8、198.18/15 等）。
// IPv4 映射的 IPv6 地址（::ffff:a.b.c.d）按其 IPv4 地址判断。nil 视为禁止。
func IsDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range reservedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckDialAddress 校验拨号地址（host:port，host 必须是已解析的 IP）。
func CheckDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %q is not an ip address", ErrDialAddressNotAllowed, host)
	}
	if IsDisallowedIP(ip) {
		return fmt.Errorf("%w: %s", ErrDialAddressNotAllowed, ip.String())
	}
	return nil
}

// DialControl 可直接赋给 net.Dialer.Control：每次 connect 之前校验实际 IP。
func DialControl(_ string, address string, _ syscall.RawConn) error {
	return CheckDialAddress(address)
}

// DialControlContext 返回可赋给 net.Dialer.ControlContext 的函数。
// enforce 为 nil 时总是校验；否则仅当 enforce(ctx) 为 true 时校验（用于按请求开启）。
func DialControlContext(enforce func(ctx context.Context) bool) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if enforce != nil && !enforce(ctx) {
			return nil
		}
		return DialControl(network, address, c)
	}
}
