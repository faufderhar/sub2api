package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// M-7：挂 stepUpAuth 的路由始终要求 step-up，即使 step_up_enabled=false。
func runStepUpMiddleware(t *testing.T, mw gin.HandlerFunc, prepare func(c *gin.Context)) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	reached := false
	r := gin.New()
	r.POST("/sensitive", func(c *gin.Context) {
		if prepare != nil {
			prepare(c)
		}
		c.Next()
	}, mw, func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sensitive", nil))
	return rec, reached
}

func decodeStepUpEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

func TestM7_StepUpMiddlewareIgnoresDisabledSwitch(t *testing.T) {
	settings := service.NewSettingService(&complianceGuardRepoStub{values: map[string]string{
		service.SettingKeyStepUpEnabled: "false",
	}}, &config.Config{})
	require.False(t, settings.IsStepUpEnabled(t.Context()))

	mw := gin.HandlerFunc(NewStepUpAuthMiddleware(nil, nil, settings))

	rec, reached := runStepUpMiddleware(t, mw, nil)
	require.False(t, reached, "switch off must no longer bypass stepUpAuth routes")
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	rec, reached = runStepUpMiddleware(t, mw, func(c *gin.Context) {
		c.Set("auth_method", service.AuditAuthMethodAdminAPIKey)
	})
	require.False(t, reached)
	require.Equal(t, http.StatusForbidden, rec.Code)
	body := decodeStepUpEnvelope(t, rec)
	require.Equal(t, float64(http.StatusForbidden), body["code"])
	require.Equal(t, "STEP_UP_ADMIN_API_KEY_FORBIDDEN", body["reason"])
	require.Equal(t, StepUpMachineCredentialMessage, body["message"])
}

func TestM7_StepUpContractEnvelopes(t *testing.T) {
	cases := []struct {
		name    string
		grant   bool
		totp    bool
		status  int
		reason  string
		message string
	}{
		{"required", false, true, http.StatusForbidden, "STEP_UP_REQUIRED", "需要二次验证"},
		{"totp not enabled", true, false, http.StatusForbidden, "STEP_UP_TOTP_NOT_ENABLED", "请先在个人设置中开启两步验证（TOTP）后再执行此操作"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := stepUpAuth(stubStepUpGrantChecker{granted: tc.grant}, stubStepUpUserReader{user: &service.User{ID: 1, TotpEnabled: tc.totp}}, nil)
			rec, reached := runStepUpMiddleware(t, mw, func(c *gin.Context) {
				c.Set(string(ContextKeyUser), AuthSubject{UserID: 1})
			})
			require.False(t, reached)
			require.Equal(t, tc.status, rec.Code)
			body := decodeStepUpEnvelope(t, rec)
			require.Equal(t, float64(tc.status), body["code"])
			require.Equal(t, tc.reason, body["reason"])
			require.Equal(t, tc.message, body["message"])
		})
	}

	t.Run("grant passes", func(t *testing.T) {
		mw := stepUpAuth(stubStepUpGrantChecker{granted: true}, stubStepUpUserReader{user: &service.User{ID: 1, TotpEnabled: true}}, nil)
		rec, reached := runStepUpMiddleware(t, mw, func(c *gin.Context) {
			c.Set(string(ContextKeyUser), AuthSubject{UserID: 1})
		})
		require.True(t, reached)
		require.Equal(t, http.StatusOK, rec.Code)
	})
}

// 机器凭证拒绝是一处隔离开关；默认拒绝，即使该身份已有 grant。
func TestM7_MachineCredentialRejectionIsIsolatedAndDefaultOn(t *testing.T) {
	require.True(t, stepUpRejectMachineCredentials)
	for _, method := range []string{service.AuditAuthMethodAdminAPIKey, service.AuditAuthMethodMCPOAuth, "future_machine_token"} {
		mw := stepUpAuth(stubStepUpGrantChecker{granted: true}, stubStepUpUserReader{user: &service.User{ID: 1, TotpEnabled: true}}, nil)
		rec, reached := runStepUpMiddleware(t, mw, func(c *gin.Context) {
			c.Set("auth_method", method)
			c.Set(string(ContextKeyUser), AuthSubject{UserID: 1})
		})
		require.False(t, reached, method)
		require.Equal(t, http.StatusForbidden, rec.Code, method)
	}
}
