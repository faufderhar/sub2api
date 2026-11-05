package routes

import (
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	adminhandler "github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// M-7：支付服务商创建/删除始终 step-up；配置/服务商更新由 handler 按「实际变更」判断，
// 不挂路由级 stepUpAuth；套餐、订单、退款保持原样。
func TestM7_PaymentRoutesStepUpWiring(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	noop := func(c *gin.Context) { c.Next() }
	stepUp := middleware.StepUpAuthMiddleware(func(c *gin.Context) {
		c.AbortWithStatusJSON(403, gin.H{"reason": "ROUTE_STEP_UP_MW"})
	})
	RegisterPaymentRoutes(r.Group("/api/v1"), &handler.PaymentHandler{}, &handler.PaymentWebhookHandler{}, &adminhandler.PaymentHandler{},
		middleware.JWTAuthMiddleware(noop), middleware.AdminAuthMiddleware(noop), middleware.AuditLogMiddleware(noop), stepUp, nil, nil, nil)

	serve := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/v1/admin/payment/providers"},
		{"DELETE", "/api/v1/admin/payment/providers/1"},
	} {
		w := serve(tc.method, tc.path)
		require.Equal(t, 403, w.Code, tc.method+" "+tc.path)
		require.Contains(t, w.Body.String(), "ROUTE_STEP_UP_MW")
	}
	for _, tc := range []struct{ method, path string }{
		{"PUT", "/api/v1/admin/payment/config"},
		{"PUT", "/api/v1/admin/payment/providers/1"},
		{"POST", "/api/v1/admin/payment/plans"},
		{"PUT", "/api/v1/admin/payment/plans/1"},
		{"DELETE", "/api/v1/admin/payment/plans/1"},
		{"POST", "/api/v1/admin/payment/orders/1/refund"},
		{"POST", "/api/v1/admin/payment/orders/1/cancel"},
	} {
		w := serve(tc.method, tc.path)
		require.NotContains(t, w.Body.String(), "ROUTE_STEP_UP_MW", tc.method+" "+tc.path)
	}
}
