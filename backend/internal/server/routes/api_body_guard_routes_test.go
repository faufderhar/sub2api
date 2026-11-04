package routes

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Every large-body exemption must point at a real admin route; a typo would
// silently cap that endpoint at 1MB.
func TestAPILargeBodyRoutesExist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	passthrough := func(c *gin.Context) { c.Next() }
	RegisterAdminRoutes(router.Group("/api/v1"), &handler.Handlers{Admin: &handler.AdminHandlers{}},
		servermiddleware.AdminAuthMiddleware(passthrough), servermiddleware.AuditLogMiddleware(passthrough),
		servermiddleware.StepUpAuthMiddleware(passthrough), nil, nil)

	registered := map[string]bool{}
	for _, r := range router.Routes() {
		registered[r.Method+" "+r.Path] = true
	}
	for _, key := range servermiddleware.APILargeBodyRoutes {
		require.True(t, registered[key], "large-body route %q is not registered", key)
	}
}

func TestCommonEventLoggingRouteRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterCommonRoutes(router, servermiddleware.APIBodyGuard(servermiddleware.APIBodyGuardConfig{
		MaxBodyBytes: 1 << 20,
		ReadTimeout:  time.Second,
	}))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/event_logging/batch", bytes.NewReader(make([]byte, 2<<20))))
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/event_logging/batch", bytes.NewReader([]byte(`{}`))))
	require.Equal(t, http.StatusOK, w.Code)
}
