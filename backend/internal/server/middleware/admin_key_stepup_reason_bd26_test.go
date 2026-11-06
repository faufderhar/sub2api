//go:build unit

package middleware

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// BD2-6：admin API key 调 7 条 step-up 密钥管理路由时，仍然 403 拒绝、不进 handler，
// 但响应带约定的 reason=STEP_UP_ADMIN_API_KEY_FORBIDDEN（而不是 FORBIDDEN）。
func bd26Router(t *testing.T, policy adminaccess.Policy, confirmFull bool) (*gin.Engine, string) {
	t.Helper()
	repo := &adminAuthKeyRepo{}
	settings := service.NewSettingService(nil, nil)
	settings.SetScopedAdminKeyRepository(repo)
	key, _, err := settings.CreateScopedAdminKey(context.Background(), service.ScopedAdminKeyInput{Name: "bd26", Enabled: true, ConfirmFullAccess: confirmFull, Policy: policy}, 9)
	require.NoError(t, err)
	users := service.NewUserService(&stubUserRepo{getByID: func(context.Context, int64) (*service.User, error) {
		return &service.User{ID: 9, Role: service.RoleAdmin, Status: service.StatusActive}, nil
	}}, nil, nil, nil)
	r := gin.New()
	r.Use(gin.HandlerFunc(NewAdminAuthMiddleware(nil, users, settings, nil)))
	for _, route := range StepUpAdminKeyManagementRoutes() {
		method, path, _ := strings.Cut(route, " ")
		r.Handle(method, path, func(c *gin.Context) { t.Fatalf("handler must not run for %s %s", c.Request.Method, c.FullPath()) })
	}
	r.GET("/api/v1/admin/settings/admin-api-key", func(c *gin.Context) { t.Fatal("handler must not run") })
	r.GET("/api/v1/admin/settings/admin-api-keys", func(c *gin.Context) { t.Fatal("handler must not run") })
	return r, key
}

func bd26Concrete(path string) string { return strings.ReplaceAll(path, ":id", "key-1") }

func bd26AssertStepUpReason(t *testing.T, r *gin.Engine, key string) {
	t.Helper()
	routes := StepUpAdminKeyManagementRoutes()
	require.Len(t, routes, 7)
	for _, route := range routes {
		method, path, _ := strings.Cut(route, " ")
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, bd26Concrete(path), nil)
		req.Header.Set("x-api-key", key)
		r.ServeHTTP(w, req)
		require.Equal(t, 403, w.Code, route)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), route)
		require.Equal(t, "STEP_UP_ADMIN_API_KEY_FORBIDDEN", body["reason"], route+" "+w.Body.String())
		require.Equal(t, StepUpMachineCredentialMessage, body["message"], route)
	}
	// 非 step-up 的读路由仍按原样拒绝为 FORBIDDEN。
	for _, path := range []string{"/api/v1/admin/settings/admin-api-key", "/api/v1/admin/settings/admin-api-keys"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("x-api-key", key)
		r.ServeHTTP(w, req)
		require.Equal(t, 403, w.Code, path)
		require.Contains(t, w.Body.String(), `"FORBIDDEN"`, path)
		require.NotContains(t, w.Body.String(), "STEP_UP_", path)
	}
}

func TestBD26FullAccessScopedKeyGetsStepUpReasonOnKeyManagementRoutes(t *testing.T) {
	r, key := bd26Router(t, adminaccess.Policy{FullAccess: true}, true)
	bd26AssertStepUpReason(t, r, key)
}

func TestBD26LimitedScopedKeyGetsStepUpReasonOnKeyManagementRoutes(t *testing.T) {
	r, key := bd26Router(t, adminaccess.Policy{GlobalPermissions: []string{"users.read"}}, false)
	bd26AssertStepUpReason(t, r, key)
}

func TestBD26LegacyAdminKeyGetsStepUpReasonOnKeyManagementRoutes(t *testing.T) {
	r, _ := bd26Router(t, adminaccess.Policy{FullAccess: true}, true)
	bd26AssertStepUpReason(t, r, "admin-legacy-key")
}

func TestBD26OtherDeniedRoutesKeepForbidden(t *testing.T) {
	r, key := bd26Router(t, adminaccess.Policy{GlobalPermissions: []string{"users.read"}}, false)
	r.POST("/api/v1/admin/unknown", func(c *gin.Context) { t.Fatal("handler must not run") })
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/admin/unknown", nil)
	req.Header.Set("x-api-key", key)
	r.ServeHTTP(w, req)
	require.Equal(t, 403, w.Code)
	require.Contains(t, w.Body.String(), `"FORBIDDEN"`)
	require.NotContains(t, w.Body.String(), "STEP_UP_")
}
