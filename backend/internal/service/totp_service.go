package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var (
	ErrTotpNotEnabled      = infraerrors.BadRequest("TOTP_NOT_ENABLED", "totp feature is not enabled")
	ErrTotpAlreadyEnabled  = infraerrors.BadRequest("TOTP_ALREADY_ENABLED", "totp is already enabled for this account")
	ErrTotpNotSetup        = infraerrors.BadRequest("TOTP_NOT_SETUP", "totp is not set up for this account")
	ErrTotpInvalidCode     = infraerrors.BadRequest("TOTP_INVALID_CODE", "invalid totp code")
	ErrTotpSetupExpired    = infraerrors.BadRequest("TOTP_SETUP_EXPIRED", "totp setup session expired")
	ErrTotpTooManyAttempts = infraerrors.TooManyRequests("TOTP_TOO_MANY_ATTEMPTS", "too many verification attempts, please try again later")
	ErrVerifyCodeRequired  = infraerrors.BadRequest("VERIFY_CODE_REQUIRED", "email verification code is required")
	ErrPasswordRequired    = infraerrors.BadRequest("PASSWORD_REQUIRED", "password is required")
)

// TotpCache defines cache operations for TOTP service
type TotpCache interface {
	// Setup session methods
	GetSetupSession(ctx context.Context, userID int64) (*TotpSetupSession, error)
	SetSetupSession(ctx context.Context, userID int64, session *TotpSetupSession, ttl time.Duration) error
	DeleteSetupSession(ctx context.Context, userID int64) error

	// Login session methods (for 2FA login flow)
	GetLoginSession(ctx context.Context, tempToken string) (*TotpLoginSession, error)
	SetLoginSession(ctx context.Context, tempToken string, session *TotpLoginSession, ttl time.Duration) error
	DeleteLoginSession(ctx context.Context, tempToken string) error

	// Rate limiting
	IncrementVerifyAttempts(ctx context.Context, userID int64) (int, error)
	GetVerifyAttempts(ctx context.Context, userID int64) (int, error)
	ClearVerifyAttempts(ctx context.Context, userID int64) error
	// ReserveVerifyAttempt atomically reserves one verification attempt before the
	// code is checked ("increment first, then verify"). It returns allowed=false
	// once maxAttempts attempts have been reserved inside the attempt window, so
	// concurrent requests can never evaluate more than maxAttempts codes.
	ReserveVerifyAttempt(ctx context.Context, userID int64, maxAttempts int) (allowed bool, err error)
	// MarkCodeStepUsed atomically records that the TOTP time step was consumed.
	// It returns false when this step (or a later one) was already used, which
	// rejects replays of a code inside its validity window.
	MarkCodeStepUsed(ctx context.Context, userID int64, step int64, ttl time.Duration) (bool, error)

	// Step-up grant methods (敏感操作 sudo 窗口)
	SetStepUpGrant(ctx context.Context, userID int64, sessionKey string, ttl time.Duration) error
	HasStepUpGrant(ctx context.Context, userID int64, sessionKey string) (bool, error)
}

// SecretEncryptor defines encryption operations for TOTP secrets
type SecretEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// TotpSetupSession represents a TOTP setup session
type TotpSetupSession struct {
	Secret     string // Plain text TOTP secret (not encrypted yet)
	SetupToken string // Random token to verify setup request
	CreatedAt  time.Time
}

// TotpLoginSession represents a pending 2FA login session
type TotpLoginSession struct {
	UserID           int64
	Email            string
	TokenExpiry      time.Time
	PendingOAuthBind *PendingOAuthBindLoginSession `json:"pending_oauth_bind,omitempty"`
}

type PendingOAuthBindLoginSession struct {
	PendingSessionToken string `json:"pending_session_token,omitempty"`
	BrowserSessionKey   string `json:"browser_session_key,omitempty"`
}

// TotpStatus represents the TOTP status for a user
type TotpStatus struct {
	Enabled        bool       `json:"enabled"`
	EnabledAt      *time.Time `json:"enabled_at,omitempty"`
	FeatureEnabled bool       `json:"feature_enabled"`
}

// TotpSetupResponse represents the response for initiating TOTP setup
type TotpSetupResponse struct {
	Secret     string `json:"secret"`
	QRCodeURL  string `json:"qr_code_url"`
	SetupToken string `json:"setup_token"`
	Countdown  int    `json:"countdown"` // seconds until setup expires
}

const (
	totpSetupTTL    = 5 * time.Minute
	totpLoginTTL    = 5 * time.Minute
	totpAttemptsTTL = 15 * time.Minute
	maxTotpAttempts = 5
	// totpPeriodSeconds / totpSkewSteps mirror totp.Validate defaults (30s, ±1 step).
	totpPeriodSeconds = 30
	totpSkewSteps     = 1
	// totpUsedStepTTL keeps the last used step long enough to cover the whole
	// validity window (current step ± skew) with margin.
	totpUsedStepTTL = 5 * time.Minute
	totpIssuer      = "Sub2API"
)

// TotpService handles TOTP operations
type TotpService struct {
	userRepo          UserRepository
	encryptor         SecretEncryptor
	cache             TotpCache
	settingService    *SettingService
	emailService      *EmailService
	emailQueueService *EmailQueueService
}

// NewTotpService creates a new TOTP service
func NewTotpService(
	userRepo UserRepository,
	encryptor SecretEncryptor,
	cache TotpCache,
	settingService *SettingService,
	emailService *EmailService,
	emailQueueService *EmailQueueService,
) *TotpService {
	return &TotpService{
		userRepo:          userRepo,
		encryptor:         encryptor,
		cache:             cache,
		settingService:    settingService,
		emailService:      emailService,
		emailQueueService: emailQueueService,
	}
}

// GetStatus returns the TOTP status for a user
func (s *TotpService) GetStatus(ctx context.Context, userID int64) (*TotpStatus, error) {
	featureEnabled := s.settingService.IsTotpEnabled(ctx)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	return &TotpStatus{
		Enabled:        user.TotpEnabled,
		EnabledAt:      user.TotpEnabledAt,
		FeatureEnabled: featureEnabled,
	}, nil
}

// usesEmailVerification 判断 TOTP 启用/停用时的身份校验方式。
// 管理员一律使用密码校验：管理员账号的邮箱常为占位地址收不到验证码，
// 且管理员凭证失守时攻击者往往同时控制通知邮箱，邮箱验证码不构成有效防线。
// 普通用户维持原有行为：开启邮箱验证时用邮箱验证码，否则用密码。
func (s *TotpService) usesEmailVerification(ctx context.Context, user *User) bool {
	return user.Role != RoleAdmin && s.settingService.IsEmailVerifyEnabled(ctx)
}

// verifyIdentity 按 usesEmailVerification 的结果校验邮箱验证码或密码。
func (s *TotpService) verifyIdentity(ctx context.Context, user *User, emailCode, password string) error {
	if s.usesEmailVerification(ctx, user) {
		if emailCode == "" {
			return ErrVerifyCodeRequired
		}
		return s.emailService.VerifyCode(ctx, user.Email, emailCode)
	}
	if password == "" {
		return ErrPasswordRequired
	}
	if !user.CheckPassword(password) {
		return ErrPasswordIncorrect
	}
	return nil
}

// InitiateSetup starts the TOTP setup process
// If email verification is enabled, emailCode is required; otherwise password is required
func (s *TotpService) InitiateSetup(ctx context.Context, userID int64, emailCode, password string) (*TotpSetupResponse, error) {
	// Check if TOTP feature is enabled globally
	if !s.settingService.IsTotpEnabled(ctx) {
		return nil, ErrTotpNotEnabled
	}

	// Get user and check if TOTP is already enabled
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	if user.TotpEnabled {
		return nil, ErrTotpAlreadyEnabled
	}

	if err := s.verifyIdentity(ctx, user, emailCode, password); err != nil {
		return nil, err
	}

	// Generate a new TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: user.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// Generate a random setup token
	setupToken, err := generateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate setup token: %w", err)
	}

	// Store the setup session in cache
	session := &TotpSetupSession{
		Secret:     key.Secret(),
		SetupToken: setupToken,
		CreatedAt:  time.Now(),
	}

	if err := s.cache.SetSetupSession(ctx, userID, session, totpSetupTTL); err != nil {
		return nil, fmt.Errorf("store setup session: %w", err)
	}

	return &TotpSetupResponse{
		Secret:     key.Secret(),
		QRCodeURL:  key.URL(),
		SetupToken: setupToken,
		Countdown:  int(totpSetupTTL.Seconds()),
	}, nil
}

// CompleteSetup completes the TOTP setup by verifying the code
func (s *TotpService) CompleteSetup(ctx context.Context, userID int64, totpCode, setupToken string) error {
	// Check if TOTP feature is enabled globally
	if !s.settingService.IsTotpEnabled(ctx) {
		return ErrTotpNotEnabled
	}

	// Get the setup session
	session, err := s.cache.GetSetupSession(ctx, userID)
	if err != nil {
		return ErrTotpSetupExpired
	}

	if session == nil {
		return ErrTotpSetupExpired
	}

	// Verify the setup token (constant-time comparison)
	if subtle.ConstantTimeCompare([]byte(session.SetupToken), []byte(setupToken)) != 1 {
		return ErrTotpSetupExpired
	}

	// T-1：绑定校验同样接入次数限制（与登录 2FA / step-up 共用按用户计数的窗口，
	// D10a：保持按用户，不按 IP）。先占用一次尝试再校验；占满后即使正确码也被拒。
	// 计数存储不可用时 fail-closed。
	allowed, err := s.cache.ReserveVerifyAttempt(ctx, userID, maxTotpAttempts)
	if err != nil {
		slog.Warn("totp_complete_setup_reserve_attempt_failed", "user_id", userID, "error", err)
		return ErrServiceUnavailable
	}
	if !allowed {
		return s.tooManyAttemptsError(ctx, userID)
	}

	// Verify the TOTP code
	if !totp.Validate(totpCode, session.Secret) {
		return ErrTotpInvalidCode
	}

	slog.Debug("totp_complete_setup_before_encrypt",
		"user_id", userID,
		"secret_len", len(session.Secret))

	// Encrypt the secret
	encryptedSecret, err := s.encryptor.Encrypt(session.Secret)
	if err != nil {
		return fmt.Errorf("encrypt totp secret: %w", err)
	}

	slog.Debug("totp_complete_setup_encrypted",
		"user_id", userID,
		"encrypted_len", len(encryptedSecret))

	// Verify encryption by decrypting
	decrypted, decErr := s.encryptor.Decrypt(encryptedSecret)
	if decErr != nil {
		slog.Debug("totp_complete_setup_verify_failed",
			"user_id", userID,
			"error", decErr)
	} else {
		slog.Debug("totp_complete_setup_verified",
			"user_id", userID,
			"original_len", len(session.Secret),
			"decrypted_len", len(decrypted),
			"match", session.Secret == decrypted)
	}

	// Update user with encrypted TOTP secret
	if err := s.userRepo.UpdateTotpSecret(ctx, userID, &encryptedSecret); err != nil {
		return fmt.Errorf("update totp secret: %w", err)
	}

	// Enable TOTP for the user
	if err := s.userRepo.EnableTotp(ctx, userID); err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}

	// Clean up the setup session
	_ = s.cache.DeleteSetupSession(ctx, userID)
	_ = s.cache.ClearVerifyAttempts(ctx, userID)

	return nil
}

// Disable disables TOTP for a user
// If email verification is enabled, emailCode is required; otherwise password is required
func (s *TotpService) Disable(ctx context.Context, userID int64, emailCode, password string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	if !user.TotpEnabled {
		return ErrTotpNotSetup
	}

	if err := s.verifyIdentity(ctx, user, emailCode, password); err != nil {
		return err
	}

	// Disable TOTP
	if err := s.userRepo.DisableTotp(ctx, userID); err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}

	return nil
}

// VerifyCode verifies a TOTP code for a user
func (s *TotpService) VerifyCode(ctx context.Context, userID int64, code string) error {
	slog.Debug("totp_verify_code_called",
		"user_id", userID,
		"code_len", len(code))

	// Reserve an attempt atomically before checking the code ("increment first,
	// then verify"), so concurrent guesses can never exceed maxTotpAttempts.
	// Fail closed: if the attempt store is unavailable the code is not checked.
	allowed, err := s.cache.ReserveVerifyAttempt(ctx, userID, maxTotpAttempts)
	if err != nil {
		slog.Warn("totp_verify_reserve_attempt_failed", "user_id", userID, "error", err)
		return ErrServiceUnavailable
	}
	if !allowed {
		return s.tooManyAttemptsError(ctx, userID)
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.Debug("totp_verify_get_user_failed",
			"user_id", userID,
			"error", err)
		return infraerrors.InternalServer("TOTP_VERIFY_ERROR", "failed to verify totp code")
	}

	if !user.TotpEnabled || user.TotpSecretEncrypted == nil {
		slog.Debug("totp_verify_not_setup",
			"user_id", userID,
			"enabled", user.TotpEnabled,
			"has_secret", user.TotpSecretEncrypted != nil)
		return ErrTotpNotSetup
	}

	slog.Debug("totp_verify_encrypted_secret",
		"user_id", userID,
		"encrypted_len", len(*user.TotpSecretEncrypted))

	// Decrypt the secret
	secret, err := s.encryptor.Decrypt(*user.TotpSecretEncrypted)
	if err != nil {
		slog.Debug("totp_verify_decrypt_failed",
			"user_id", userID,
			"error", err)
		return infraerrors.InternalServer("TOTP_VERIFY_ERROR", "failed to verify totp code")
	}

	slog.Debug("totp_verify_decrypted",
		"user_id", userID,
		"secret_len", len(secret))

	// Verify the code (same parameters as totp.Validate) and learn which time step matched.
	now := time.Now().UTC()
	step, valid := matchTotpStep(code, secret, now)
	slog.Debug("totp_verify_result",
		"user_id", userID,
		"valid", valid,
		"secret_len", len(secret),
		"server_time", now.Format(time.RFC3339))

	if !valid {
		// The attempt was already counted by ReserveVerifyAttempt.
		return ErrTotpInvalidCode
	}

	// Anti-replay: a step can be consumed once; a code from a step that is not
	// newer than the last successfully used one is rejected.
	firstUse, err := s.cache.MarkCodeStepUsed(ctx, userID, step, totpUsedStepTTL)
	if err != nil {
		slog.Warn("totp_verify_mark_used_failed", "user_id", userID, "error", err)
		return ErrServiceUnavailable
	}
	if !firstUse {
		slog.Info("totp_verify_replay_rejected", "user_id", userID)
		return ErrTotpInvalidCode
	}

	// Clear attempt counter on success
	_ = s.cache.ClearVerifyAttempts(ctx, userID)

	return nil
}

// matchTotpStep validates code against secret for the current step ± totpSkewSteps
// using the same primitive and parameters as totp.Validate (HOTP/SHA1, 6 digits,
// 30s period) and returns the matched time-step counter.
func matchTotpStep(code, secret string, now time.Time) (int64, bool) {
	current := now.Unix() / totpPeriodSeconds
	opts := hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	// Same order as totp.ValidateCustom: current step first, then ±1 (totpSkewSteps).
	for _, offset := range []int64{0, totpSkewSteps, -totpSkewSteps} {
		step := current + offset
		ok, err := hotp.ValidateCustom(code, uint64(step), secret, opts)
		if err != nil {
			return 0, false
		}
		if ok {
			return step, true
		}
	}
	return 0, false
}

// StepUpGrantTTL 敏感操作 step-up 验证的有效窗口（sudo 模式）。
const StepUpGrantTTL = 15 * time.Minute

// VerifyStepUp 校验 TOTP 码并授予当前会话一段时间的 step-up 权限。
// 返回授权有效期，供前端展示/设置提醒。
func (s *TotpService) VerifyStepUp(ctx context.Context, userID int64, sessionKey, code string) (time.Duration, error) {
	if err := s.VerifyCode(ctx, userID, code); err != nil {
		return 0, err
	}
	if err := s.cache.SetStepUpGrant(ctx, userID, sessionKey, StepUpGrantTTL); err != nil {
		return 0, fmt.Errorf("store step-up grant: %w", err)
	}
	return StepUpGrantTTL, nil
}

// HasStepUpGrant 检查当前会话是否在 step-up 有效期内。
func (s *TotpService) HasStepUpGrant(ctx context.Context, userID int64, sessionKey string) (bool, error) {
	return s.cache.HasStepUpGrant(ctx, userID, sessionKey)
}

// CreateLoginSession creates a temporary login session for 2FA
func (s *TotpService) CreateLoginSession(ctx context.Context, userID int64, email string) (string, error) {
	return s.createLoginSession(ctx, userID, email, nil)
}

// CreatePendingOAuthBindLoginSession creates a temporary 2FA session that will
// finalize a pending OAuth bind after the TOTP code is verified.
func (s *TotpService) CreatePendingOAuthBindLoginSession(
	ctx context.Context,
	userID int64,
	email string,
	pendingSessionToken string,
	browserSessionKey string,
) (string, error) {
	return s.createLoginSession(ctx, userID, email, &PendingOAuthBindLoginSession{
		PendingSessionToken: pendingSessionToken,
		BrowserSessionKey:   browserSessionKey,
	})
}

func (s *TotpService) createLoginSession(
	ctx context.Context,
	userID int64,
	email string,
	pendingOAuthBind *PendingOAuthBindLoginSession,
) (string, error) {
	// Generate a random temp token
	tempToken, err := generateRandomToken(32)
	if err != nil {
		return "", fmt.Errorf("generate temp token: %w", err)
	}

	session := &TotpLoginSession{
		UserID:           userID,
		Email:            email,
		TokenExpiry:      time.Now().Add(totpLoginTTL),
		PendingOAuthBind: pendingOAuthBind,
	}

	if err := s.cache.SetLoginSession(ctx, tempToken, session, totpLoginTTL); err != nil {
		return "", fmt.Errorf("store login session: %w", err)
	}

	return tempToken, nil
}

// GetLoginSession retrieves a login session
func (s *TotpService) GetLoginSession(ctx context.Context, tempToken string) (*TotpLoginSession, error) {
	return s.cache.GetLoginSession(ctx, tempToken)
}

// DeleteLoginSession deletes a login session
func (s *TotpService) DeleteLoginSession(ctx context.Context, tempToken string) error {
	return s.cache.DeleteLoginSession(ctx, tempToken)
}

// IsTotpEnabledForUser checks if TOTP is enabled for a specific user
func (s *TotpService) IsTotpEnabledForUser(ctx context.Context, userID int64) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("get user: %w", err)
	}
	return user.TotpEnabled, nil
}

// MaskEmail masks an email address for display
func MaskEmail(email string) string {
	if len(email) < 3 {
		return "***"
	}

	atIdx := -1
	for i, c := range email {
		if c == '@' {
			atIdx = i
			break
		}
	}

	if atIdx == -1 || atIdx < 1 {
		return email[:1] + "***"
	}

	localPart := email[:atIdx]
	domain := email[atIdx:]

	if len(localPart) <= 2 {
		return localPart[:1] + "***" + domain
	}

	return localPart[:1] + "***" + localPart[len(localPart)-1:] + domain
}

// generateRandomToken generates a random hex-encoded token
func generateRandomToken(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// VerificationMethod represents the method required for TOTP operations
type VerificationMethod struct {
	Method string `json:"method"` // "email" or "password"
}

// GetVerificationMethod returns the verification method for TOTP operations.
// 与 verifyIdentity 保持同一判定：管理员一律返回 password。
func (s *TotpService) GetVerificationMethod(ctx context.Context, userID int64) (*VerificationMethod, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if s.usesEmailVerification(ctx, user) {
		return &VerificationMethod{Method: "email"}, nil
	}
	return &VerificationMethod{Method: "password"}, nil
}

// SendVerifyCode sends an email verification code for TOTP operations
func (s *TotpService) SendVerifyCode(ctx context.Context, userID int64, locale ...string) error {
	// Check if email verification is enabled
	if !s.settingService.IsEmailVerifyEnabled(ctx) {
		return infraerrors.BadRequest("EMAIL_VERIFY_NOT_ENABLED", "email verification is not enabled")
	}

	// Get user email
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Get site name for email
	siteName := s.settingService.GetSiteName(ctx)

	// Send verification code via queue
	return s.emailQueueService.EnqueueVerifyCode(user.Email, siteName, firstEmailLocale(locale))
}

// TotpAttemptTTLReader 是 TotpCache 的可选扩展：返回按用户尝试计数窗口的剩余时间。
// 返回 0 表示未知（键不存在或无过期时间）。
type TotpAttemptTTLReader interface {
	GetVerifyAttemptsTTL(ctx context.Context, userID int64) (time.Duration, error)
}

// TotpRetryAfterMetadataKey 是 429 TOTP_TOO_MANY_ATTEMPTS 错误 metadata 中的剩余秒数，
// response.ErrorFrom 会据此写 Retry-After 响应头（BD2-4）。
const TotpRetryAfterMetadataKey = "retry_after"

// tooManyAttemptsError 返回带剩余锁定秒数的 ErrTotpTooManyAttempts（BD2-4）。
// 剩余 TTL 不可得时回退为整个窗口长度。
func (s *TotpService) tooManyAttemptsError(ctx context.Context, userID int64) error {
	return ErrTotpTooManyAttempts.WithMetadata(map[string]string{
		TotpRetryAfterMetadataKey: strconv.Itoa(totpRetryAfterSeconds(ctx, s.cache, userID)),
	})
}

func totpRetryAfterSeconds(ctx context.Context, cache TotpCache, userID int64) int {
	fallback := int(totpAttemptsTTL / time.Second)
	reader, ok := cache.(TotpAttemptTTLReader)
	if !ok {
		return fallback
	}
	ttl, err := reader.GetVerifyAttemptsTTL(ctx, userID)
	if err != nil || ttl <= 0 {
		return fallback
	}
	secs := int((ttl + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	if secs > fallback {
		secs = fallback
	}
	return secs
}
