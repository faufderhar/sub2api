//go:build unit

package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// M-6：Grok 语音请求体有界读取，超限返回 errGrokVoiceBodyTooLarge（handler 映射为 413）。
func TestM6_GrokVoiceBodyBoundedRead(t *testing.T) {
	old := grokVoiceGatewayMaxBodyBytes
	grokVoiceGatewayMaxBodyBytes = 16
	t.Cleanup(func() { grokVoiceGatewayMaxBodyBytes = old })

	newCtx := func(n int) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewReader(bytes.Repeat([]byte("a"), n)))
		return c
	}
	body, err := readGrokVoiceGatewayBody(newCtx(16))
	require.NoError(t, err)
	require.Len(t, body, 16)

	_, err = readGrokVoiceGatewayBody(newCtx(17))
	require.ErrorIs(t, err, errGrokVoiceBodyTooLarge)
}
