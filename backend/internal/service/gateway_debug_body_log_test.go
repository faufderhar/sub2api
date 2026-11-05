//go:build unit

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestL6_DebugBodyLogFileIs0600EvenIfPreexisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway_debug.log")
	require.NoError(t, os.WriteFile(path, []byte("old\n"), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))

	l, err := openDebugBodyLog(path, 1<<20, time.Hour)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	l.WriteString("hello\n")
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestL6_GatewayServiceInitCreates0600FileAnd0700Dir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	path := filepath.Join(dir, "dbg.log")
	s := &GatewayService{}
	s.initDebugGatewayBodyFile(path)
	l := s.debugGatewayBodyFile.Load()
	require.NotNil(t, l)
	defer func() { _ = l.Close() }()
	s.debugLogGatewaySnapshot("CLIENT_ORIGINAL", nil, []byte(`{"a":1}`), nil)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dinfo, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dinfo.Mode().Perm())
}

func TestL6_DebugBodyLogRotatesOnSizeAndKeepsOneBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.log")
	l, err := openDebugBodyLog(path, 100, time.Hour)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	for i := 0; i < 10; i++ {
		l.WriteString(strings.Repeat("x", 40))
	}
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.LessOrEqual(t, info.Size(), int64(100))
	rinfo, err := os.Stat(path + ".1")
	require.NoError(t, err)
	require.LessOrEqual(t, rinfo.Size(), int64(100))
	require.Equal(t, os.FileMode(0o600), rinfo.Mode().Perm())
	_, err = os.Stat(path + ".2")
	require.True(t, os.IsNotExist(err))

	l.WriteString(strings.Repeat("y", 500)) // 单条超限被截断
	info, _ = os.Stat(path)
	require.LessOrEqual(t, info.Size(), int64(100))
}

func TestL6_DebugBodyLogRotatesOnAgeAndPrunesExpiredBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.log")
	l, err := openDebugBodyLog(path, 1<<20, time.Hour)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	base := time.Now()
	l.now = func() time.Time { return base }
	l.openedAt = base
	l.WriteString("first\n")

	// 当前文件打开超过保留时长 → 轮转；最近写入未过期的旧文件保留为 .1
	l.now = func() time.Time { return base.Add(61 * time.Minute) }
	require.NoError(t, os.Chtimes(path, base.Add(30*time.Minute), base.Add(30*time.Minute)))
	l.WriteString("second\n")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "second\n", string(b))
	old, err := os.ReadFile(path + ".1")
	require.NoError(t, err)
	require.Equal(t, "first\n", string(old))

	// .1 最后写入已超过保留时长 → 下次轮转/打开时删除
	require.NoError(t, os.Chtimes(path+".1", base.Add(-2*time.Hour), base.Add(-2*time.Hour)))
	l.mu.Lock()
	l.pruneRotatedLocked()
	l.mu.Unlock()
	_, err = os.Stat(path + ".1")
	require.True(t, os.IsNotExist(err), "expired rotated file is removed")
}

func TestL6_DebugBodyLimitsFromEnv(t *testing.T) {
	t.Setenv(debugGatewayBodyMaxMBEnv, "")
	t.Setenv(debugGatewayBodyMaxAgeHoursEnv, "")
	b, a := debugBodyLimitsFromEnv()
	require.Equal(t, int64(64<<20), b)
	require.Equal(t, 24*time.Hour, a)
	t.Setenv(debugGatewayBodyMaxMBEnv, "8")
	t.Setenv(debugGatewayBodyMaxAgeHoursEnv, "2")
	b, a = debugBodyLimitsFromEnv()
	require.Equal(t, int64(8<<20), b)
	require.Equal(t, 2*time.Hour, a)
}
