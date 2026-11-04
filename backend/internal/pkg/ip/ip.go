// Package ip 提供客户端 IP 地址提取工具。
package ip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

const forwardedIPSettingsKey = "sub2api.forwarded_ip_settings"

type forwardedIPSettings struct {
	trustForwarded bool
	headers        []string
}

// SetForwardedIPSettings snapshots the forwarded-IP mode and custom header list
// for this request.
func SetForwardedIPSettings(c *gin.Context, enabled bool, headers []string) {
	if c == nil {
		return
	}
	c.Set(forwardedIPSettingsKey, forwardedIPSettings{
		trustForwarded: enabled,
		headers:        append([]string(nil), headers...),
	})
}

// SetLegacyForwardedIPTrust records whether raw forwarding headers override
// Gin's server.trusted_proxies chain for this request.
func SetLegacyForwardedIPTrust(c *gin.Context, enabled bool) {
	SetForwardedIPSettings(c, enabled, nil)
}

func requestForwardedIPSettings(c *gin.Context) (forwardedIPSettings, bool) {
	if c == nil {
		return forwardedIPSettings{}, false
	}
	value, ok := c.Get(forwardedIPSettingsKey)
	if !ok {
		return forwardedIPSettings{}, false
	}
	settings, ok := value.(forwardedIPSettings)
	return settings, ok
}

func requestUsesLegacyForwardedIPTrust(c *gin.Context) bool {
	settings, ok := requestForwardedIPSettings(c)
	// 安全默认：没有请求级快照时不启用旧版转发头接管。
	return ok && settings.trustForwarded
}

// trustedProxyPrefixes 是 server.trusted_proxies 解析后的可信代理网段。
// 只有直连地址（RemoteAddr）落在这些网段内时，才会解析任何转发头。
var trustedProxyPrefixes atomic.Pointer[[]netip.Prefix]

// SetTrustedProxies 设置可信代理列表（CIDR 或单个 IP），返回无法解析的条目。
// 传入空列表表示不信任任何代理：所有转发头都会被忽略，客户端 IP 即直连地址。
func SetTrustedProxies(entries []string) []string {
	prefixes := make([]netip.Prefix, 0, len(entries))
	var invalid []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				invalid = append(invalid, entry)
				continue
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			invalid = append(invalid, entry)
			continue
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	trustedProxyPrefixes.Store(&prefixes)
	return invalid
}

// TrustedProxiesConfigured 报告当前是否配置了至少一个可信代理网段。
func TrustedProxiesConfigured() bool {
	p := trustedProxyPrefixes.Load()
	return p != nil && len(*p) > 0
}

func isTrustedProxyAddr(ipStr string) bool {
	p := trustedProxyPrefixes.Load()
	if p == nil || len(*p) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, prefix := range *p {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// remotePeerIP 返回 TCP 直连地址（不含端口）。
func remotePeerIP(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	return normalizeIP(c.Request.RemoteAddr)
}

// ClientIP 是全项目唯一的"取客户端 IP"入口：IP 白名单/黑名单、限流、审计日志、
// 会话绑定、请求日志都应通过它（或基于它的 SessionBinding 快照）取值。
//
// 规则：
//  1. 直连地址不在 server.trusted_proxies 内时，忽略所有转发头，直接返回直连地址；
//  2. 直连地址可信且旧版兼容开关（security.trust_forwarded_ip_for_api_key_acl）
//     开启时，按旧版优先级解析自定义头、CF-Connecting-IP、X-Real-IP、X-Forwarded-For；
//  3. 直连地址可信且兼容开关关闭（默认）时，从右往左遍历 X-Forwarded-For，
//     跳过可信代理，取第一个不可信地址；没有 X-Forwarded-For 时使用 X-Real-IP。
func ClientIP(c *gin.Context) string {
	peer := remotePeerIP(c)
	if peer == "" || !isTrustedProxyAddr(peer) {
		return peer
	}
	if requestUsesLegacyForwardedIPTrust(c) {
		return legacyForwardedClientIP(c, peer)
	}
	if resolved := trustedChainClientIP(c); resolved != "" {
		return resolved
	}
	return peer
}

// forwardedForChain 把所有 X-Forwarded-For 头行按出现顺序用逗号拼接。
// HAProxy option forwardfor、部分 Envoy / Go ReverseProxy 会追加一行新的 XFF
// 而不是合并到已有行；只读第一行会让客户端伪造的值被当作代理写入的值。
func forwardedForChain(h http.Header) string {
	values := h.Values("X-Forwarded-For")
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	default:
		return strings.Join(values, ",")
	}
}

// singleValueForwardedHeader 返回单值转发头（X-Real-IP、CF-Connecting-IP 等）的值。
// 这类头按约定只应出现一次；出现多行说明客户端自带了一份、代理又追加了一份，
// 无法判断哪一行可信，因此整体视为不可信（返回空）。
func singleValueForwardedHeader(h http.Header, name string) string {
	values := h.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

// trustedChainClientIP 与 Gin 的 ClientIP 语义一致：依次检查 X-Forwarded-For（多行按顺序拼接）、
// X-Real-IP（多行视为不可信），从右往左跳过可信代理，返回第一个不可信地址；遇到非法值时放弃该请求头。
func trustedChainClientIP(c *gin.Context) string {
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		var value string
		if header == "X-Forwarded-For" {
			value = forwardedForChain(c.Request.Header)
		} else {
			value = singleValueForwardedHeader(c.Request.Header, header)
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		items := strings.Split(value, ",")
		resolved := ""
		for i := len(items) - 1; i >= 0; i-- {
			candidate := normalizeValidIP(items[i])
			if candidate == "" {
				resolved = ""
				break
			}
			resolved = candidate
			if !isTrustedProxyAddr(candidate) {
				break
			}
		}
		if resolved != "" {
			return resolved
		}
	}
	return ""
}

func legacyForwardedClientIP(c *gin.Context, peer string) string {
	settings, _ := requestForwardedIPSettings(c)
	customIP, customFallback := resolveCustomForwardedClientIP(c, settings.headers)
	if customIP != "" {
		return customIP
	}

	// Preserve the historical precedence used by existing reverse-proxy
	// deployments, while skipping an internal proxy address when a public XFF
	// value is available. This covers Docker/Nginx setups that accidentally
	// write the bridge address into X-Real-IP.
	legacyIP, legacyFallback := resolveLegacyForwardedHeaderIP(c)
	if legacyIP != "" {
		return legacyIP
	}
	if customFallback != "" {
		return customFallback
	}
	if legacyFallback != "" {
		return legacyFallback
	}
	return peer
}

// GetClientIP is kept for existing callers; it is identical to ClientIP.
func GetClientIP(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return ClientIP(c)
}

func resolveCustomForwardedClientIP(c *gin.Context, headers []string) (string, string) {
	if c == nil {
		return "", ""
	}
	var fallback string
	for _, header := range headers {
		for _, value := range c.Request.Header.Values(header) {
			for _, candidate := range strings.Split(value, ",") {
				parsed := net.ParseIP(strings.TrimSpace(candidate))
				if parsed == nil {
					continue
				}
				normalized := parsed.String()
				if isPrivateIP(normalized) {
					if fallback == "" {
						fallback = normalized
					}
					continue
				}
				return normalized, fallback
			}
		}
	}
	return "", fallback
}

func resolveLegacyForwardedHeaderIP(c *gin.Context) (string, string) {
	var fallback string
	if forwarded := normalizeValidIP(singleValueForwardedHeader(c.Request.Header, "CF-Connecting-IP")); forwarded != "" {
		fallback = forwarded
		if !isPrivateIP(forwarded) {
			return forwarded, fallback
		}
	}
	if realIP := normalizeValidIP(singleValueForwardedHeader(c.Request.Header, "X-Real-IP")); realIP != "" {
		if fallback == "" {
			fallback = realIP
		}
		if !isPrivateIP(realIP) {
			return realIP, fallback
		}
	}
	if xff := forwardedForChain(c.Request.Header); xff != "" {
		ips := strings.Split(xff, ",")
		for _, candidate := range ips {
			candidate = normalizeValidIP(candidate)
			if candidate != "" && !isPrivateIP(candidate) {
				return candidate, fallback
			}
		}
		if fallback == "" {
			for _, candidate := range ips {
				if candidate = normalizeValidIP(candidate); candidate != "" {
					fallback = candidate
					break
				}
			}
		}
	}
	return "", fallback
}

// GetTrustedClientIP is kept for existing callers; it is identical to ClientIP.
func GetTrustedClientIP(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return ClientIP(c)
}

// GetSecurityClientIP is kept for existing callers; it is identical to ClientIP.
// The trustForwarded argument is ignored: the per-request snapshot written by
// SetForwardedIPSettings (SessionBindingContext) is authoritative, and
// forwarded headers are only honoured when the direct peer is a trusted proxy.
func GetSecurityClientIP(c *gin.Context, _ bool) string {
	if c == nil {
		return ""
	}
	return ClientIP(c)
}

// normalizeIP 规范化 IP 地址，去除端口号和空格。
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	// 移除端口号（如 "192.168.1.1:8080" -> "192.168.1.1"）
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}

// normalizeValidIP 规范化并验证代理头中的候选值，避免把 unknown、主机名等非法值传给安全服务。
func normalizeValidIP(value string) string {
	normalized := normalizeIP(value)
	parsed := net.ParseIP(normalized)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// privateNets contains the private/loopback ranges skipped while selecting a
// public address from a legacy X-Forwarded-For chain.
var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR: " + cidr)
		}
		privateNets = append(privateNets, block)
	}
}

// CompiledIPRules 表示预编译的 IP 匹配规则。
// PatternCount 记录原始规则数量，用于保留“规则存在但全无效”时的行为语义。
type CompiledIPRules struct {
	CIDRs        []*net.IPNet
	IPs          []net.IP
	PatternCount int
}

// CompileIPRules 将 IP/CIDR 字符串规则预编译为可复用结构。
// 非法规则会被忽略，但 PatternCount 会保留原始规则条数。
func CompileIPRules(patterns []string) *CompiledIPRules {
	compiled := &CompiledIPRules{
		CIDRs:        make([]*net.IPNet, 0, len(patterns)),
		IPs:          make([]net.IP, 0, len(patterns)),
		PatternCount: len(patterns),
	}
	for _, pattern := range patterns {
		normalized := strings.TrimSpace(pattern)
		if normalized == "" {
			continue
		}
		if strings.Contains(normalized, "/") {
			_, cidr, err := net.ParseCIDR(normalized)
			if err != nil || cidr == nil {
				continue
			}
			compiled.CIDRs = append(compiled.CIDRs, cidr)
			continue
		}
		parsedIP := net.ParseIP(normalized)
		if parsedIP == nil {
			continue
		}
		compiled.IPs = append(compiled.IPs, parsedIP)
	}
	return compiled
}

func matchesCompiledRules(parsedIP net.IP, rules *CompiledIPRules) bool {
	if parsedIP == nil || rules == nil {
		return false
	}
	for _, cidr := range rules.CIDRs {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	for _, ruleIP := range rules.IPs {
		if parsedIP.Equal(ruleIP) {
			return true
		}
	}
	return false
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, block := range privateNets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// MatchesPattern 检查 IP 是否匹配指定的模式（支持单个 IP 或 CIDR）。
// pattern 可以是：
// - 单个 IP: "192.168.1.100"
// - CIDR 范围: "192.168.1.0/24"
func MatchesPattern(clientIP, pattern string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	// 尝试解析为 CIDR
	if strings.Contains(pattern, "/") {
		_, cidr, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}

	// 作为单个 IP 处理
	patternIP := net.ParseIP(pattern)
	if patternIP == nil {
		return false
	}
	return ip.Equal(patternIP)
}

// MatchesAnyPattern 检查 IP 是否匹配任意一个模式。
func MatchesAnyPattern(clientIP string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchesPattern(clientIP, pattern) {
			return true
		}
	}
	return false
}

// CheckIPRestriction 检查 IP 是否被 API Key 的 IP 限制允许。
// 返回值：(是否允许, 拒绝原因)
// 逻辑：
// 1. 先检查黑名单，如果在黑名单中则直接拒绝
// 2. 如果白名单不为空，IP 必须在白名单中
// 3. 如果白名单为空，允许访问（除非被黑名单拒绝）
func CheckIPRestriction(clientIP string, whitelist, blacklist []string) (bool, string) {
	return CheckIPRestrictionWithCompiledRules(
		clientIP,
		CompileIPRules(whitelist),
		CompileIPRules(blacklist),
	)
}

// CheckIPRestrictionWithCompiledRules 使用预编译规则检查 IP 是否允许访问。
func CheckIPRestrictionWithCompiledRules(clientIP string, whitelist, blacklist *CompiledIPRules) (bool, string) {
	// 规范化 IP
	clientIP = normalizeIP(clientIP)
	if clientIP == "" {
		return false, "access denied"
	}
	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil {
		return false, "access denied"
	}

	// 1. 检查黑名单
	if blacklist != nil && blacklist.PatternCount > 0 && matchesCompiledRules(parsedIP, blacklist) {
		return false, "access denied"
	}

	// 2. 检查白名单（如果设置了白名单，IP 必须在其中）
	if whitelist != nil && whitelist.PatternCount > 0 && !matchesCompiledRules(parsedIP, whitelist) {
		return false, "access denied"
	}

	return true, ""
}

// ValidateIPPattern 验证 IP 或 CIDR 格式是否有效。
func ValidateIPPattern(pattern string) bool {
	if strings.Contains(pattern, "/") {
		_, _, err := net.ParseCIDR(pattern)
		return err == nil
	}
	return net.ParseIP(pattern) != nil
}

// ValidateIPPatterns 验证多个 IP 或 CIDR 格式。
// 返回无效的模式列表。
func ValidateIPPatterns(patterns []string) []string {
	var invalid []string
	for _, p := range patterns {
		if !ValidateIPPattern(p) {
			invalid = append(invalid, p)
		}
	}
	return invalid
}
