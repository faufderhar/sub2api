package config

import (
	"os"
	"strings"
	"testing"
)

// TestMain：M-5 起未配置 TOTP_ENCRYPTION_KEY 时 Load 会在数据目录（默认当前目录）落盘生成的 key。
// 大量用例把 DATA_DIR 置空，为避免在源码目录写文件，这里默认给一个显式测试 key；
// 需要覆盖自动生成路径的用例自行 t.Setenv("TOTP_ENCRYPTION_KEY", "") 并指定临时 DATA_DIR。
func TestMain(m *testing.M) {
	if strings.TrimSpace(os.Getenv("TOTP_ENCRYPTION_KEY")) == "" {
		_ = os.Setenv("TOTP_ENCRYPTION_KEY", strings.Repeat("ab", 32))
	}
	os.Exit(m.Run())
}
