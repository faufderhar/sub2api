package middleware

import (
	"context"
	"fmt"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// StepUpAuthMiddleware 敏感操作 step-up 2FA 门控中间件类型。
type StepUpAuthMiddleware gin.HandlerFunc

// stepUpGrantChecker 抽象 TOTP step-up 授权检查能力（由 TotpService 实现）。
type stepUpGrantChecker interface {
	HasStepUpGrant(ctx context.Context, userID int64, sessionKey string) (bool, error)
}

// stepUpUserReader 抽象用户读取能力（检查 TOTP 是否启用）。
type stepUpUserReader interface {
	GetByID(ctx context.Context, id int64) (*service.User, error)
}

// stepUpSettingReader 抽象 step-up 功能开关读取能力（由 SettingService 实现）。
type stepUpSettingReader interface {
	IsStepUpEnabled(ctx context.Context) bool
}

// StepUpSessionKey 计算 step-up 授权的会话键：
// 优先绑定当前会话（refresh token family），无会话 ID 的旧 token 退化为用户级键。
func StepUpSessionKey(c *gin.Context, userID int64) string {
	if sid := c.GetString(ContextKeySessionID); sid != "" {
		return sid
	}
	return fmt.Sprintf("u%d", userID)
}

// Step-up 失败时返回给前端的文案（与《第二轮前后端接口约定》一致，前端可直接展示）。
const (
	StepUpRequiredMessage          = "需要二次验证"
	StepUpTotpNotEnabledMessage    = "请先在个人设置中开启两步验证（TOTP）后再执行此操作"
	StepUpMachineCredentialMessage = "该操作需要已完成两步验证的管理员会话"
)

// NewStepUpAuthMiddleware 创建敏感操作 step-up 2FA 门控中间件。
//
// M-7 / D2a：挂在本中间件上的路由**始终**要求 step-up，不再读取 step_up_enabled
// 功能开关（该开关现在只影响仍走 EnforceStepUp 的按请求内容触发的门控；创建/提升管理员与 MCP 只读授权已改为始终门控）。
// 通过条件（全部满足）：
//  1. 必须是 JWT 认证的真人会话——admin API key（机器凭证）一律拒绝
//  2. 当前用户已启用 TOTP（未启用则拒绝并提示先启用 2FA）
//  3. 当前会话在有效期内完成过 TOTP step-up 验证（POST /api/v1/user/totp/step-up）
//
// 失败响应使用可区分的错误码，前端据此弹出 TOTP 验证对话框后重试。
func NewStepUpAuthMiddleware(
	totpService *service.TotpService,
	userService *service.UserService,
	settingService *service.SettingService,
) StepUpAuthMiddleware {
	_ = settingService // 保留参数以兼容 wire 装配；中间件不再读取功能开关（M-7/D2a）。
	return StepUpAuthMiddleware(stepUpAuth(totpService, userService, nil))
}

// stepUpSettingsOrNil 将可能为 nil 的具体指针归一化为接口，
// 避免 typed-nil 装箱后绕过 enforceStepUp 内的 nil 判断。
func stepUpSettingsOrNil(settingService *service.SettingService) stepUpSettingReader {
	if settingService == nil {
		return nil
	}
	return settingService
}

func stepUpAuth(grantChecker stepUpGrantChecker, userReader stepUpUserReader, settings stepUpSettingReader) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !enforceStepUp(c, grantChecker, userReader, settings) {
			return
		}
		c.Next()
	}
}

// EnforceStepUp 对当前请求执行与 StepUpAuthMiddleware 相同语义的 step-up 门控，
// 供 handler 在需要按请求内容条件触发时调用（如仅当把用户角色提升为管理员时）。
// 校验失败时写入错误响应并中止请求，返回 false；通过返回 true。
func EnforceStepUp(
	c *gin.Context,
	totpService *service.TotpService,
	userService *service.UserService,
	settingService *service.SettingService,
) bool {
	return enforceStepUp(c, totpService, userService, stepUpSettingsOrNil(settingService))
}

// EnforceStepUpAlways 与 EnforceStepUp 语义相同但不读取功能开关，无条件执行门控。
// 供调用方已确知门控必须生效的场景使用（如"关闭 step-up 开关"本身：调用方刚从
// 持久化设置读到开关为开启状态，不应依赖二次读取——读取失败会导致门控被跳过）。
func EnforceStepUpAlways(
	c *gin.Context,
	totpService *service.TotpService,
	userService *service.UserService,
) bool {
	return enforceStepUp(c, totpService, userService, nil)
}

// MachineCredentialReason allowlists interactive browser sessions: the user
// router leaves auth_method empty and the admin router sets "jwt". Every other
// method (admin API keys, MCP OAuth, future credential types) is a machine
// credential and is denied by default; the reason distinguishes known kinds.
func MachineCredentialReason(c *gin.Context) (string, bool) {
	switch c.GetString("auth_method") {
	case "", service.AuditAuthMethodJWT:
		return "", false
	case service.AuditAuthMethodAdminAPIKey:
		return "STEP_UP_ADMIN_API_KEY_FORBIDDEN", true
	case service.AuditAuthMethodMCPOAuth:
		return "STEP_UP_MCP_OAUTH_FORBIDDEN", true
	default:
		return "STEP_UP_MACHINE_CREDENTIAL_FORBIDDEN", true
	}
}

// stepUpRejectMachineCredentials 控制 step-up 门控是否拒绝机器凭证（admin API key、
// MCP OAuth 等无法完成 TOTP 的凭证）。M-7：默认拒绝。
// 项目经理/用户若决定放行机器凭证，只需改这一处（以及 rejectMachineCredentialForStepUp）。
var stepUpRejectMachineCredentials = true

// rejectMachineCredentialForStepUp 是 step-up 门控里唯一的「机器凭证」检查，单独隔离。
// 拒绝时写入 403 并返回 true。
func rejectMachineCredentialForStepUp(c *gin.Context) bool {
	if !stepUpRejectMachineCredentials {
		return false
	}
	reason, machine := MachineCredentialReason(c)
	if !machine {
		return false
	}
	abortStepUp(c, 403, reason, StepUpMachineCredentialMessage)
	return true
}

// abortStepUp 以统一错误信封写出 step-up 错误：
// {"code": <HTTP 状态码>, "message": "...", "reason": "STEP_UP_*"}（第二轮接口约定）。
func abortStepUp(c *gin.Context, status int, reason, message string) {
	response.ErrorWithDetails(c, status, message, reason, nil)
	c.Abort()
}

func enforceStepUp(c *gin.Context, grantChecker stepUpGrantChecker, userReader stepUpUserReader, settings stepUpSettingReader) bool {
	// settings 非 nil 时（仅 EnforceStepUp 的按内容触发门控）功能开关关闭则放行；
	// settings 为 nil 时始终门控（StepUpAuthMiddleware 与 EnforceStepUpAlways）。
	if settings != nil && !settings.IsStepUpEnabled(c.Request.Context()) {
		return true
	}

	if rejectMachineCredentialForStepUp(c) {
		return false
	}

	subject, ok := GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		AbortWithError(c, 401, "UNAUTHORIZED", "Authorization required")
		return false
	}

	user, err := userReader.GetByID(c.Request.Context(), subject.UserID)
	if err != nil {
		AbortWithError(c, 500, "INTERNAL_ERROR", "Failed to load user")
		return false
	}
	if !user.TotpEnabled {
		abortStepUp(c, 403, "STEP_UP_TOTP_NOT_ENABLED", StepUpTotpNotEnabledMessage)
		return false
	}

	sessionKey := StepUpSessionKey(c, subject.UserID)
	granted, err := grantChecker.HasStepUpGrant(c.Request.Context(), subject.UserID, sessionKey)
	if err != nil {
		// 安全门控故障时选择 fail-closed。
		AbortWithError(c, 503, "STEP_UP_UNAVAILABLE", "Step-up verification service unavailable")
		return false
	}
	if !granted {
		abortStepUp(c, 403, "STEP_UP_REQUIRED", StepUpRequiredMessage)
		return false
	}

	return true
}
