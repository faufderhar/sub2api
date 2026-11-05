package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// M-7：PUT /admin/settings 中支付字段仅在实际变化时要求 step-up。

type paymentStepUpUserRepo struct {
	service.UserRepository
	user *service.User
}

func (r *paymentStepUpUserRepo) GetByID(ctx context.Context, id int64) (*service.User, error) {
	u := *r.user
	return &u, nil
}

func (r *paymentStepUpUserRepo) GetUserAvatar(ctx context.Context, userID int64) (*service.UserAvatar, error) {
	return nil, nil
}

type paymentStepUpTotpCache struct {
	service.TotpCache
	granted bool
}

func (c *paymentStepUpTotpCache) HasStepUpGrant(ctx context.Context, userID int64, sessionKey string) (bool, error) {
	return c.granted, nil
}

func newPaymentStepUpHandler(t *testing.T, stored map[string]string, granted bool) (*SettingHandler, *settingHandlerRepoStub) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	repo := &settingHandlerRepoStub{values: stored}
	cfg := &config.Config{Default: config.DefaultConfig{UserConcurrency: 5}}
	svc := service.NewSettingService(repo, cfg)
	paymentCfg := service.NewPaymentConfigService(nil, repo, nil)
	h := NewSettingHandler(svc, nil, nil, nil, paymentCfg, nil, nil)
	userRepo := &paymentStepUpUserRepo{user: &service.User{ID: 1, Role: service.RoleAdmin, Status: service.StatusActive, TotpEnabled: true}}
	totp := service.NewTotpService(userRepo, nil, &paymentStepUpTotpCache{granted: granted}, svc, nil, nil)
	users := service.NewUserService(userRepo, repo, nil, nil)
	h.SetStepUpDeps(totp, users)
	return h, repo
}

// grantStepUpForTest 注入一个已启用 TOTP 且持有 step-up grant 的管理员身份依赖，
// 供既有「修改支付字段」的测试在 M-7 门控下继续覆盖持久化逻辑。
func grantStepUpForTest(h *SettingHandler, svc *service.SettingService, repo service.SettingRepository) {
	userRepo := &paymentStepUpUserRepo{user: &service.User{ID: 1, Role: service.RoleAdmin, Status: service.StatusActive, TotpEnabled: true}}
	totp := service.NewTotpService(userRepo, nil, &paymentStepUpTotpCache{granted: true}, svc, nil, nil)
	h.SetStepUpDeps(totp, service.NewUserService(userRepo, repo, nil, nil))
}

func storedPaymentSettings() map[string]string {
	return map[string]string{
		service.SettingPaymentEnabled:    "true",
		service.SettingMinRechargeAmount: "5",
		service.SettingMaxRechargeAmount: "500",
	}
}

func asJWTAdmin(c *gin.Context) {
	c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 1})
	c.Set("auth_method", "jwt")
}

func TestM7_UpdateSettingsUnchangedPaymentFieldsSkipStepUp(t *testing.T) {
	h, repo := newPaymentStepUpHandler(t, storedPaymentSettings(), false)

	// 前端常规保存：原样回传 GET 得到的支付字段。
	rec := doUpdateSettings(t, h, map[string]any{
		"registration_enabled": true,
		"payment_enabled":      true,
		"payment_min_amount":   5,
		"payment_max_amount":   500,
	}, asJWTAdmin)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "STEP_UP_REQUIRED")
	require.Contains(t, []string{"5", "5.00"}, repo.values[service.SettingMinRechargeAmount])
}

func TestM7_UpdateSettingsNoPaymentFieldsSkipStepUp(t *testing.T) {
	h, _ := newPaymentStepUpHandler(t, storedPaymentSettings(), false)

	rec := doUpdateSettings(t, h, map[string]any{"registration_enabled": true}, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestM7_UpdateSettingsChangedPaymentFieldRequiresStepUp(t *testing.T) {
	h, repo := newPaymentStepUpHandler(t, storedPaymentSettings(), false)

	rec := doUpdateSettings(t, h, map[string]any{
		"payment_enabled":    true,
		"payment_min_amount": 10,
		"payment_max_amount": 500,
	}, asJWTAdmin)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "STEP_UP_REQUIRED", body["reason"])
	require.Equal(t, "需要二次验证", body["message"])
	require.Equal(t, "5", repo.values[service.SettingMinRechargeAmount], "rejected request must not write")
}

func TestM7_UpdateSettingsChangedVisibleMethodRequiresStepUp(t *testing.T) {
	h, _ := newPaymentStepUpHandler(t, storedPaymentSettings(), false)

	rec := doUpdateSettings(t, h, map[string]any{"payment_visible_method_alipay_enabled": true}, asJWTAdmin)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "STEP_UP_REQUIRED")
}

func TestM7_UpdateSettingsChangedPaymentFieldWithGrantSucceeds(t *testing.T) {
	h, repo := newPaymentStepUpHandler(t, storedPaymentSettings(), true)

	rec := doUpdateSettings(t, h, map[string]any{
		"payment_enabled":    true,
		"payment_min_amount": 10,
	}, asJWTAdmin)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "10.00", repo.values[service.SettingMinRechargeAmount])
}

func TestM7_UpdateSettingsChangedPaymentFieldRejectsAdminAPIKey(t *testing.T) {
	h, repo := newPaymentStepUpHandler(t, storedPaymentSettings(), true)

	rec := doUpdateSettings(t, h, map[string]any{"payment_enabled": false}, func(c *gin.Context) {
		c.Set("auth_method", service.AuditAuthMethodAdminAPIKey)
	})

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "STEP_UP_ADMIN_API_KEY_FORBIDDEN")
	require.Equal(t, "true", repo.values[service.SettingPaymentEnabled])
}

func TestM7_PaymentConfigFieldsChangedComparators(t *testing.T) {
	cur := &service.PaymentConfig{
		EnabledTypes:       []string{"alipay", "wxpay"},
		RechargeBonusTiers: []service.RechargeBonusTier{{MinAmount: 10, BonusPercent: 5}, {MinAmount: 100, BonusPercent: 10}},
		RechargeBonusMode:  "bonus",
		HelpText:           "hi",
	}
	same := UpdateSettingsRequest{
		PaymentEnabledTypes:      []string{"wxpay", "alipay"},
		PaymentRechargeBonusMode: strPtr(""),
		PaymentHelpText:          strPtr(" hi "),
	}
	require.False(t, paymentConfigFieldsChanged(same, cur))

	diffTypes := UpdateSettingsRequest{PaymentEnabledTypes: []string{"alipay"}}
	require.True(t, paymentConfigFieldsChanged(diffTypes, cur))
}

func strPtr(s string) *string { return &s }
