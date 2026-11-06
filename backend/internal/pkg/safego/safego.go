// Package safego 提供带 panic 恢复的 goroutine 启动器（L-3 第二轮）。
//
// gin 的 Recovery 只覆盖处理请求的 goroutine；后台 goroutine（SSE 读取协程、定时任务等）
// 中的 panic 会直接让整个进程退出。safego.Go 在 recover 后记录错误日志（含堆栈）并累加指标，
// 进程继续运行。
//
// 注意：recover 只能吞掉 panic，不能修复状态。被恢复的函数里用 defer 做的清理（close channel、
// 释放 buffer、wg.Done 等）仍会照常执行，因为 defer 在 panic 展开时运行。
package safego

import (
	"context"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

var (
	totalPanics atomic.Int64
	byName      sync.Map // name -> *atomic.Int64
)

// Go 在新 goroutine 中运行 fn，并在 fn panic 时恢复、记日志、计数。
// ctx 会原样传给 fn（safego 本身不取消 fn），也用于日志上下文；nil 时用 context.Background()。
func Go(ctx context.Context, name string, fn func(ctx context.Context)) {
	if fn == nil {
		return
	}
	go runDetached(ctx, name, fn)
}

// runDetached 是 Go 启动的 goroutine 主体：直接沿用调用方传入的 ctx（Run 负责 nil 兜底）。
func runDetached(ctx context.Context, name string, fn func(ctx context.Context)) {
	Run(ctx, name, fn)
}

// Run 在当前 goroutine 同步运行 fn，并恢复 panic（用于已有 go 语句或 worker 循环内部）。
// 返回 fn 是否发生了 panic。
func Run(ctx context.Context, name string, fn func(ctx context.Context)) (panicked bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			record(ctx, name, r, debug.Stack())
		}
	}()
	fn(ctx)
	return false
}

// Tick 同步执行定时任务的单次 tick 并恢复 panic：一次 tick panic 不会终止整个定时循环。
func Tick(name string, fn func()) {
	if fn == nil {
		return
	}
	Run(context.Background(), name, func(context.Context) { fn() })
}

// Recover 用于 `defer safego.Recover(name)`：放在已有 goroutine 的第一条语句，
// 使其后注册的 defer（close channel、归还 buffer 等）先执行，再由这里恢复 panic。
// recover() 只有在被 defer 直接调用的函数里才生效，所以必须写成 `defer safego.Recover(...)`。
func Recover(name string) {
	if r := recover(); r != nil {
		record(context.Background(), name, r, debug.Stack())
	}
}

func record(ctx context.Context, name string, r any, stack []byte) {
	totalPanics.Add(1)
	if counter := counterFor(name, true); counter != nil {
		counter.Add(1)
	}
	logger.FromContext(ctx).Error("goroutine panic recovered",
		zap.String("component", "safego"),
		zap.String("goroutine", name),
		zap.String("panic", fmt.Sprint(r)),
		zap.ByteString("stack", stack),
	)
}

// counterFor 返回名称对应的计数器；create 为 true 时不存在就创建。
func counterFor(name string, create bool) *atomic.Int64 {
	var v any
	if create {
		v, _ = byName.LoadOrStore(name, new(atomic.Int64))
	} else {
		var ok bool
		if v, ok = byName.Load(name); !ok {
			return nil
		}
	}
	counter, _ := v.(*atomic.Int64)
	return counter
}

// TotalPanics 返回进程启动以来被恢复的 panic 总数（指标）。
func TotalPanics() int64 { return totalPanics.Load() }

// PanicCount 返回指定名称的 goroutine 被恢复的 panic 次数。
func PanicCount(name string) int64 {
	if counter := counterFor(name, false); counter != nil {
		return counter.Load()
	}
	return 0
}

// Snapshot 返回按名称汇总的 panic 次数（只包含发生过 panic 的名称）。
func Snapshot() map[string]int64 {
	out := map[string]int64{}
	byName.Range(func(k, v any) bool {
		name, okName := k.(string)
		counter, okCounter := v.(*atomic.Int64)
		if okName && okCounter {
			out[name] = counter.Load()
		}
		return true
	})
	return out
}

// Names 返回发生过 panic 的名称（排序），便于排查。
func Names() []string {
	snap := Snapshot()
	names := make([]string, 0, len(snap))
	for k := range snap {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
