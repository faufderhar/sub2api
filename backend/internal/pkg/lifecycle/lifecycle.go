// Package lifecycle 提供进程级的关停上下文，供脱离请求生命周期的后台任务使用。
//
// 请求处理中启动的异步任务不能直接使用请求 ctx（响应返回即取消），也不应使用
// context.Background()（无超时、关停时无法取消，gosec G118）。Detached 返回的
// ctx 保留父 ctx 的值、不随请求取消，但有超时上限，并在进程关停时被取消。
package lifecycle

import (
	"context"
	"sync"
	"time"
)

var (
	mu         sync.Mutex
	rootCtx    context.Context
	rootCancel context.CancelFunc
)

func init() {
	rootCtx, rootCancel = context.WithCancel(context.Background())
}

// Context 返回进程级上下文；Shutdown 后被取消。
func Context() context.Context {
	mu.Lock()
	defer mu.Unlock()
	return rootCtx
}

// Shutdown 取消进程级上下文，通知所有 Detached 后台任务停止。可重复调用。
func Shutdown() {
	mu.Lock()
	cancel := rootCancel
	mu.Unlock()
	cancel()
}

// Detached 基于 parent 的值创建一个不随 parent 取消、带 timeout 上限、
// 并在进程关停时取消的上下文。timeout<=0 时仅受关停控制。
func Detached(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	base := context.WithoutCancel(parent)
	var ctx context.Context
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(base, timeout)
	} else {
		ctx, cancel = context.WithCancel(base)
	}
	stop := context.AfterFunc(Context(), cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// resetForTest 仅供测试恢复全局状态。
func resetForTest() {
	mu.Lock()
	defer mu.Unlock()
	rootCtx, rootCancel = context.WithCancel(context.Background())
}
