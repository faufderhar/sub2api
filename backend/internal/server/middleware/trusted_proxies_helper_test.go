package middleware

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// useTrustedProxies 同时设置 Gin 引擎与统一 ClientIP 使用的可信代理列表，
// 等价于生产环境 configureTrustedProxies 的效果；测试结束后恢复为不信任任何代理。
func useTrustedProxies(t *testing.T, engine *gin.Engine, entries []string) {
	t.Helper()
	require.NoError(t, engine.SetTrustedProxies(entries))
	require.Empty(t, ip.SetTrustedProxies(entries))
	t.Cleanup(func() { ip.SetTrustedProxies(nil) })
}
