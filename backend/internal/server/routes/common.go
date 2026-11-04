package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RegisterCommonRoutes 注册通用路由（健康检查、状态等）
// bodyGuard 用于有请求体的非网关公共路由（默认 1MB 上限，超限 413）。
func RegisterCommonRoutes(r *gin.Engine, bodyGuard ...gin.HandlerFunc) {
	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Claude Code 遥测日志（忽略，直接返回200）
	eventLogging := append(append([]gin.HandlerFunc{}, bodyGuard...), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.POST("/api/event_logging/batch", eventLogging...)

	// Setup status endpoint (always returns needs_setup: false in normal mode)
	// This is used by the frontend to detect when the service has restarted after setup
	r.GET("/setup/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"data": gin.H{
				"needs_setup": false,
				"step":        "completed",
			},
		})
	})
}
