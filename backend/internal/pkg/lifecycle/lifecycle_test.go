package lifecycle

import (
	"context"
	"testing"
	"time"
)

type ctxKey struct{}

func TestL4_DetachedSurvivesParentCancelKeepsValues(t *testing.T) {
	resetForTest()
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "v"))
	ctx, cancel := Detached(parent, time.Minute)
	defer cancel()
	cancelParent()
	if ctx.Err() != nil {
		t.Fatalf("detached ctx must not follow parent cancel: %v", ctx.Err())
	}
	if ctx.Value(ctxKey{}) != "v" {
		t.Fatal("values must be preserved")
	}
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("detached ctx must have a deadline")
	}
}

func TestL4_DetachedCancelledOnShutdown(t *testing.T) {
	resetForTest()
	defer resetForTest()
	ctx, cancel := Detached(context.Background(), time.Hour)
	defer cancel()
	Shutdown()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("detached ctx not cancelled on shutdown")
	}
	Shutdown() // idempotent
}

func TestL4_DetachedTimeout(t *testing.T) {
	resetForTest()
	ctx, cancel := Detached(context.Background(), 20*time.Millisecond)
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("timeout not applied")
	}
}
