//go:build unit

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// BD2-3：已安装模式的路由（SetupRouter/registerRoutes 及 routes 包）不注册 /setup/* 安装路由，
// 因此安装完成后 POST /setup/install 等返回 404。接口约定据此写明「已安装 → 404」；
// 本测试防止将来在已安装路由里意外挂上安装接口而改变该约定。
func TestBD23_InstalledRouterDoesNotRegisterSetupRoutes(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	more, err := filepath.Glob(filepath.Join("routes", "*.go"))
	require.NoError(t, err)
	files = append(files, more...)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		src := string(b)
		require.NotContains(t, src, "setup.RegisterRoutes", f)
		require.NotContains(t, src, `"/setup/install"`, f)
		require.NotContains(t, src, `Group("/setup")`, f)
	}
}
