//go:build unit

package routes

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	adminhandler "github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestScopedAdminKeyManagementRoutesRequireStepUp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	stepUp := middleware.StepUpAuthMiddleware(func(c *gin.Context) { c.AbortWithStatusJSON(403, gin.H{"reason": "STEP_UP_REQUIRED"}) })
	RegisterAdminRoutes(r.Group("/api/v1"), &handler.Handlers{Admin: &handler.AdminHandlers{Setting: adminhandler.NewSettingHandler(nil, nil, nil, nil, nil, nil, nil)}}, middleware.AdminAuthMiddleware(func(c *gin.Context) { c.Set("auth_method", "jwt"); c.Next() }), middleware.AuditLogMiddleware(func(c *gin.Context) { c.Next() }), stepUp, nil, nil)
	for _, test := range []struct{ method, path string }{
		{"POST", "/api/v1/admin/settings/admin-api-key/regenerate"},
		{"DELETE", "/api/v1/admin/settings/admin-api-key"},
		{"POST", "/api/v1/admin/settings/admin-api-keys"},
		{"PUT", "/api/v1/admin/settings/admin-api-keys/key-1"},
		{"POST", "/api/v1/admin/settings/admin-api-keys/key-1/rotate"},
		{"DELETE", "/api/v1/admin/settings/admin-api-keys/key-1"},
		{"DELETE", "/api/v1/admin/settings/admin-api-keys/key-1/record"},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
		require.Equal(t, 403, w.Code, test.method+" "+test.path)
		require.Contains(t, w.Body.String(), "STEP_UP_REQUIRED")
	}
}

// BD2-6：middleware 里的 step-up 密钥管理路由清单必须与实际注册的路由一致：
// /settings/admin-api-key* 下所有非 GET 路由都在清单里，清单里的每条都已注册。
func TestBD26StepUpAdminKeyRouteListMatchesRegistration(t *testing.T) {
	r := gin.New()
	stepUp := middleware.StepUpAuthMiddleware(func(c *gin.Context) { c.Next() })
	RegisterAdminRoutes(r.Group("/api/v1"), &handler.Handlers{Admin: &handler.AdminHandlers{Setting: adminhandler.NewSettingHandler(nil, nil, nil, nil, nil, nil, nil)}}, middleware.AdminAuthMiddleware(func(c *gin.Context) { c.Next() }), middleware.AuditLogMiddleware(func(c *gin.Context) { c.Next() }), stepUp, nil, nil)
	registered := map[string]bool{}
	var writes []string
	for _, info := range r.Routes() {
		key := info.Method + " " + info.Path
		registered[key] = true
		if info.Method != "GET" && strings.HasPrefix(info.Path, "/api/v1/admin/settings/admin-api-key") {
			writes = append(writes, key)
		}
	}
	list := middleware.StepUpAdminKeyManagementRoutes()
	for _, route := range list {
		require.True(t, registered[route], "route in list but not registered: "+route)
	}
	require.ElementsMatch(t, list, writes)
}
