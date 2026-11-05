package service

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// L-6：网关调试请求体落盘（SUB2API_DEBUG_GATEWAY_BODY）。
// 内容含完整提示词，因此：
//   - 文件权限 0600、新建目录 0700（已存在的文件也会被收紧为 0600）；
//   - 单文件大小上限（默认 64MB，SUB2API_DEBUG_GATEWAY_BODY_MAX_MB），超限轮转为 <path>.1（只保留 1 份旧文件）；
//   - 保留时长上限（默认 24h，SUB2API_DEBUG_GATEWAY_BODY_MAX_AGE_HOURS）：当前文件写满时长即轮转，过期的 <path>.1 被删除。
const (
	debugGatewayBodyMaxMBEnv       = "SUB2API_DEBUG_GATEWAY_BODY_MAX_MB"
	debugGatewayBodyMaxAgeHoursEnv = "SUB2API_DEBUG_GATEWAY_BODY_MAX_AGE_HOURS"
	debugGatewayBodyDefaultMaxMB   = 64
	debugGatewayBodyDefaultMaxAge  = 24 * time.Hour
	debugGatewayBodyFileMode       = 0o600
	debugGatewayBodyDirMode        = 0o700
)

type debugBodyLog struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	size     int64
	openedAt time.Time
	maxBytes int64
	maxAge   time.Duration
	now      func() time.Time
}

func debugBodyLimitsFromEnv() (int64, time.Duration) {
	maxBytes := int64(debugGatewayBodyDefaultMaxMB) << 20
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(debugGatewayBodyMaxMBEnv))); err == nil && v > 0 {
		maxBytes = int64(v) << 20
	}
	maxAge := debugGatewayBodyDefaultMaxAge
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(debugGatewayBodyMaxAgeHoursEnv))); err == nil && v > 0 {
		maxAge = time.Duration(v) * time.Hour
	}
	return maxBytes, maxAge
}

func openDebugBodyLog(path string, maxBytes int64, maxAge time.Duration) (*debugBodyLog, error) {
	l := &debugBodyLog{path: path, maxBytes: maxBytes, maxAge: maxAge, now: time.Now}
	if err := l.open(); err != nil {
		return nil, err
	}
	l.pruneRotatedLocked()
	return l, nil
}

func (l *debugBodyLog) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, debugGatewayBodyFileMode) //nolint:gosec // G304/G703: path 仅来自启动环境变量（运维配置）
	if err != nil {
		return err
	}
	// 已存在的旧文件（可能是 0644）同样收紧。
	if err := f.Chmod(debugGatewayBodyFileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod debug log: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.file = f
	l.size = info.Size()
	l.openedAt = l.now()
	if info.Size() > 0 {
		l.openedAt = info.ModTime()
	}
	return nil
}

func (l *debugBodyLog) rotatedPath() string { return l.path + ".1" }

func (l *debugBodyLog) pruneRotatedLocked() {
	info, err := os.Stat(l.rotatedPath())
	if err == nil && l.now().Sub(info.ModTime()) > l.maxAge {
		_ = os.Remove(l.rotatedPath())
	}
}

func (l *debugBodyLog) rotateLocked() error {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	if err := os.Rename(l.path, l.rotatedPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := l.open(); err != nil {
		return err
	}
	l.openedAt = l.now()
	l.pruneRotatedLocked()
	return nil
}

// WriteString 写入一条快照；超过大小或时长上限时先轮转。单条超过上限时截断。
func (l *debugBodyLog) WriteString(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return
	}
	if int64(len(s)) > l.maxBytes {
		s = s[:l.maxBytes]
	}
	if l.size+int64(len(s)) > l.maxBytes || l.now().Sub(l.openedAt) > l.maxAge {
		if err := l.rotateLocked(); err != nil {
			slog.Error("rotate gateway debug log failed", "path", l.path, "error", err)
			return
		}
	}
	n, _ := l.file.WriteString(s)
	l.size += int64(n)
}

func (l *debugBodyLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
