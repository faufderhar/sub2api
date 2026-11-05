package setup

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const testSetupToken = "0123456789abcdef0123456789abcdef"

func newSetupTokenTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("DATA_DIR", t.TempDir()) // 无 config.yaml / install.lock → NeedsSetup()==true
	r := gin.New()
	RegisterRoutesWithToken(r, testSetupToken)
	return r
}

func doSetupRequest(r *gin.Engine, method, path, token string, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(SetupTokenHeader, token)
	}
	if remote != "" {
		req.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	return body
}

func TestL8_GenerateSetupTokenFormat(t *testing.T) {
	a, err := GenerateSetupToken()
	require.NoError(t, err)
	b, err := GenerateSetupToken()
	require.NoError(t, err)
	require.Regexp(t, regexp.MustCompile(`^[0-9a-f]{32}$`), a)
	require.NotEqual(t, a, b, "each start must regenerate the token")
}

func TestL8_RegisterRoutesLogsTokenLine(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	prev := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })

	require.NoError(t, RegisterRoutes(gin.New()))
	require.Regexp(t, regexp.MustCompile(`(?m)^\[setup\] Setup token: [0-9a-f]{32}$`), strings.TrimSpace(buf.String()))
}

func TestL8_StatusReportsTokenRequired(t *testing.T) {
	r := newSetupTokenTestRouter(t)
	rec := doSetupRequest(r, http.MethodGet, "/setup/status", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	require.Equal(t, true, data["setup_token_required"])
	require.Equal(t, true, data["needs_setup"])
}

func TestL8_ProtectedEndpointsRequireToken(t *testing.T) {
	r := newSetupTokenTestRouter(t)
	for _, path := range []string{"/setup/test-db", "/setup/test-redis", "/setup/install"} {
		rec := doSetupRequest(r, http.MethodPost, path, "", "")
		require.Equal(t, http.StatusUnauthorized, rec.Code, path)
		body := decodeEnvelope(t, rec)
		require.Equal(t, float64(401), body["code"])
		require.Equal(t, "SETUP_TOKEN_REQUIRED", body["reason"])
		require.Equal(t, "需要 setup token，请在服务启动日志中查看", body["message"])

		rec = doSetupRequest(r, http.MethodPost, path, "ffffffffffffffffffffffffffffffff", "")
		require.Equal(t, http.StatusForbidden, rec.Code, path)
		body = decodeEnvelope(t, rec)
		require.Equal(t, "SETUP_TOKEN_INVALID", body["reason"])
		require.Equal(t, "setup token 不正确，请在服务启动日志中查看最新 token", body["message"])
	}
}

func TestL8_CorrectTokenTrimmedReachesHandler(t *testing.T) {
	r := newSetupTokenTestRouter(t)
	// 空 body 会在 handler 参数校验处 400——说明已通过 token 校验。
	rec := doSetupRequest(r, http.MethodPost, "/setup/test-db", "  "+testSetupToken+"  ", "")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "SETUP_TOKEN")
}

func TestL8_InvalidTokenRateLimitedWithRetryAfter(t *testing.T) {
	r := newSetupTokenTestRouter(t)
	remote := "203.0.113.7:4321"
	for i := 0; i < setupTokenMaxFailures; i++ {
		rec := doSetupRequest(r, http.MethodPost, "/setup/install", "bad", remote)
		require.Equal(t, http.StatusForbidden, rec.Code)
	}
	rec := doSetupRequest(r, http.MethodPost, "/setup/install", testSetupToken, remote)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	body := decodeEnvelope(t, rec)
	require.Equal(t, "SETUP_TOKEN_RATE_LIMITED", body["reason"])
	require.Equal(t, "尝试过多，请稍后再试", body["message"])
	require.NotEmpty(t, rec.Header().Get("Retry-After"))

	// 其他直连 IP 不受影响。
	other := doSetupRequest(r, http.MethodPost, "/setup/test-db", testSetupToken, "198.51.100.9:1")
	require.Equal(t, http.StatusBadRequest, other.Code)
}

func TestL8_RateLimitIgnoresForwardedFor(t *testing.T) {
	r := newSetupTokenTestRouter(t)
	remote := "203.0.113.8:4321"
	for i := 0; i < setupTokenMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/setup/install", bytes.NewBufferString(`{}`))
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", "10.0.0."+string(rune('1'+i%9)))
		req.Header.Set(SetupTokenHeader, "bad")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}
	rec := doSetupRequest(r, http.MethodPost, "/setup/install", "bad", remote)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestL8_RateLimitWindowExpires(t *testing.T) {
	g := newSetupTokenGuard(testSetupToken)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	for i := 0; i < setupTokenMaxFailures; i++ {
		g.recordFailureLocked("k", now)
	}
	require.Positive(t, g.retryAfterLocked("k", now))
	require.Zero(t, g.retryAfterLocked("k", now.Add(setupTokenFailureWindow)))
}
