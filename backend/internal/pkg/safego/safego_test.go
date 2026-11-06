package safego

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// panic 在后台 goroutine 中被恢复，进程（测试二进制）不退出；defer 清理照常执行；指标累加。
func TestGoRecoversPanicAndRunsDefers(t *testing.T) {
	before := TotalPanics()
	events := make(chan int)
	Go(context.Background(), "test.sse_reader", func(context.Context) {
		defer close(events) // 消费方能看到 channel 关闭而不是永远阻塞
		events <- 1
		panic("boom")
	})
	require.Equal(t, 1, <-events)
	select {
	case _, ok := <-events:
		require.False(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("events channel was not closed after panic")
	}
	require.Eventually(t, func() bool { return TotalPanics() == before+1 }, 2*time.Second, 10*time.Millisecond)
	require.GreaterOrEqual(t, PanicCount("test.sse_reader"), int64(1))
	require.Contains(t, Names(), "test.sse_reader")
}

func TestRunReportsPanicAndContinues(t *testing.T) {
	require.True(t, Run(context.Background(), "test.ticker", func(context.Context) { panic("tick failed") }))
	require.False(t, Run(context.Background(), "test.ticker", func(context.Context) {}))
	// 模拟定时任务：单次执行 panic 不影响后续执行。
	runs := 0
	for i := 0; i < 3; i++ {
		Run(context.Background(), "test.ticker.loop", func(context.Context) {
			runs++
			if i == 0 {
				panic("first run")
			}
		})
	}
	require.Equal(t, 3, runs)
}

func TestRecoverDeferAndNilContext(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer Recover("test.recover")
		panic(struct{}{})
	}()
	wg.Wait()
	require.GreaterOrEqual(t, PanicCount("test.recover"), int64(1))

	done := make(chan struct{})
	var nilCtx context.Context
	Go(nilCtx, "test.nilctx", func(ctx context.Context) {
		require.NotNil(t, ctx)
		close(done)
	})
	<-done
	Go(context.Background(), "test.nilfn", nil)
}

func TestTickKeepsLoopAlive(t *testing.T) {
	calls := 0
	for i := 0; i < 3; i++ {
		Tick("test.tick", func() {
			calls++
			if calls == 1 {
				panic("first tick")
			}
		})
	}
	require.Equal(t, 3, calls)
	require.GreaterOrEqual(t, PanicCount("test.tick"), int64(1))
	Tick("test.tick.nil", nil)
}
