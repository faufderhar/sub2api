package service

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// L-3（第二轮）防回退：SSE 读取协程和定时任务 goroutine 必须带 safego.Recover。
// 清单与交付说明一致；新增同类 goroutine 时请一并加上并更新此表。
func TestL3_SSEReadersAndSchedulersRecoverPanics(t *testing.T) {
	want := map[string]int{
		"account_expiry_service.go":                   1,
		"antigravity_gateway_compat_stream.go":        1,
		"antigravity_gateway_streaming.go":            4,
		"antigravity_gateway_upstream.go":             1,
		"batch_image_cleanup.go":                      1,
		"bedrock_stream.go":                           1,
		"claude_code_version_sync_service.go":         1,
		"cn_provider_balance_check_service.go":        1,
		"concurrency_service.go":                      1,
		"gateway_anthropic_passthrough.go":            1,
		"gateway_upstream_response.go":                1,
		"openai_codex_version_sync_service.go":        1,
		"openai_gateway_anthropic_native_pump.go":     1,
		"openai_gateway_chat_completions.go":          1,
		"openai_gateway_messages.go":                  2,
		"openai_gateway_messages_anthropic_native.go": 1,
		"openai_gateway_response_handling.go":         1,
		"openai_images.go":                            1,
		"openai_images_responses.go":                  1,
		"openai_ws_pool.go":                           2,
		"ops_ingress_reject.go":                       1,
		"payment_order_expiry_service.go":             1,
		"pricing_service.go":                          1,
		"proxy_expiry_service.go":                     1,
		"subscription_expiry_service.go":              1,
		"usage_record_worker_pool.go":                 1,
		"user_msg_queue_service.go":                   1,
	}
	for file, min := range want {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		got := strings.Count(string(data), "defer safego.Recover(")
		require.GreaterOrEqualf(t, got, min, "%s: want >= %d safego.Recover, got %d", file, min, got)
	}
}
