package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type endlessBody struct{ read int64 }

func (b *endlessBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += int64(len(p))
	return len(p), nil
}

// M-6: an oversized (here: endless) non-streaming upstream body yields an
// explicit error instead of being buffered without bound.
func TestM6_CountTokensOversizedUpstreamBodyRejected(t *testing.T) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/input_tokens", nil)

	body := &endlessBody{}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(body),
	}}
	cfg := &config.Config{}
	cfg.Gateway.UpstreamResponseReadMaxBytes = 4096
	svc := &OpenAIGatewayService{cfg: cfg, httpUpstream: upstream}
	account := &Account{
		ID: 9001, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Concurrency: 1,
		Credentials: map[string]any{"api_key": "k", "base_url": "https://api.openai.com/v1"},
	}

	err := svc.ForwardResponsesInputTokens(context.Background(), c, account, []byte(`{"model":"gpt-5.4","input":"hi"}`))
	require.Error(t, err)
	require.ErrorContains(t, err, "too large")
	require.Equal(t, http.StatusBadGateway, recorder.Code)
	require.Less(t, body.read, int64(1<<20), "upstream body must be read only up to the limit")
}

func TestM6_DefaultMaxLineSizeIs16MB(t *testing.T) {
	require.Equal(t, 16*1024*1024, defaultMaxLineSize)
}
