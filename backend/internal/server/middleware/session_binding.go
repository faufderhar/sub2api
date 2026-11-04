package middleware

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// SessionBindingContext 全局中间件：将请求的客户端 IP 与 User-Agent 注入
// request context，供 token 签发路径（登录 / 刷新 / OAuth 回调）读取并写入会话绑定，
// 同时作为审计日志、会话绑定校验的统一客户端 IP 来源。
// IP 统一由 ip.ClientIP 计算：直连地址不在 server.trusted_proxies 内时忽略一切转发头；
// 直连地址可信时，兼容开关开启走旧版转发头优先级，关闭（默认）走可信代理链。
func SessionBindingContext(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		forwardedIPSettings := cfg.ForwardedClientIPSettings()
		ip.SetForwardedIPSettings(c, forwardedIPSettings.TrustForwardedIP, forwardedIPSettings.Headers)
		userAgent := normalizePersistentText(c.Request.UserAgent(), maxPersistentUserAgentBytes)
		c.Request.Header.Set("User-Agent", userAgent)
		binding := &service.SessionBinding{
			IP:        ip.ClientIP(c),
			UserAgent: userAgent,
		}
		c.Request = c.Request.WithContext(service.WithSessionBinding(c.Request.Context(), binding))
		c.Next()
	}
}

// requestSessionBinding 返回当前请求的会话指纹，优先取 SessionBindingContext
// 注入的解析结果（保证与 token 签发路径取值一致）；注入缺失时使用安全回退。
func requestSessionBinding(c *gin.Context) *service.SessionBinding {
	if binding := service.SessionBindingFromContext(c.Request.Context()); binding != nil {
		return binding
	}
	return &service.SessionBinding{
		IP:        ip.ClientIP(c),
		UserAgent: normalizePersistentText(c.Request.UserAgent(), maxPersistentUserAgentBytes),
	}
}

// SecurityClientIP 返回当前请求用于安全敏感判断和记录的客户端 IP：
// API Key / Scoped Admin Key 的 IP 白名单、审计日志、会话绑定、面板限流都用它。
// 值来自 SessionBindingContext 用 ip.ClientIP 计算的快照，缺失时直接调用 ip.ClientIP，
// 与 IP 维度限流（internal/middleware.clientIPForRateLimit）是同一个函数。
func SecurityClientIP(c *gin.Context) string {
	if binding := service.SessionBindingFromContext(c.Request.Context()); binding != nil &&
		strings.TrimSpace(binding.IP) != "" {
		return binding.IP
	}
	return ip.ClientIP(c)
}

// enforceSessionBinding 校验 access token 的会话指纹（IP/UA 绑定）。
// 指纹不匹配时：撤销该会话家族的所有 refresh token、写入审计安全事件、返回 401。
// 返回 false 表示请求已被中断。
//
// 兼容性：claims.BindingHash 为空（功能上线前签发的旧 token）时放行，
// 该会话在下一次 refresh 轮转时会自动获得绑定。
func enforceSessionBinding(
	c *gin.Context,
	authService *service.AuthService,
	settingService *service.SettingService,
	auditService *service.AuditLogService,
	claims *service.JWTClaims,
) bool {
	if settingService == nil || !settingService.IsSessionBindingEnabled(c.Request.Context()) {
		return true
	}
	if claims == nil || claims.BindingHash == "" {
		return true
	}
	binding := requestSessionBinding(c)
	current := binding.Hash()
	if current == "" || current == claims.BindingHash {
		return true
	}

	if authService != nil {
		_ = authService.RevokeSessionFamily(c.Request.Context(), claims.SessionID)
	}
	if auditService != nil {
		uid := claims.UserID
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		auditService.Record(&service.AuditLog{
			ActorUserID: &uid,
			ActorEmail:  claims.Email,
			ActorRole:   claims.Role,
			AuthMethod:  service.AuditAuthMethodJWT,
			Action:      service.AuditActionSessionBindingMismatch,
			Method:      c.Request.Method,
			Path:        path,
			ClientIP:    binding.IP,
			UserAgent:   normalizePersistentText(c.Request.UserAgent(), maxPersistentUserAgentBytes),
			StatusCode:  401,
		})
	}
	AbortWithError(c, 401, "SESSION_BINDING_MISMATCH", "Session network fingerprint changed, please login again")
	return false
}
