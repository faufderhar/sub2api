//go:build unit

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRefreshCookieAttributes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/login", nil)
	c.Request.Host = "127.0.0.1:8080"
	cfg := &config.Config{}
	cfg.JWT.RefreshTokenExpireDays = 30
	setRefreshCookie(c, cfg, "rt_testtoken")
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies)
	var found *http.Cookie
	for _, ck := range cookies {
		if ck.Name == refreshCookieName {
			found = ck
			break
		}
	}
	require.NotNil(t, found)
	require.Equal(t, "/api/v1/auth", found.Path)
	require.True(t, found.HttpOnly)
	require.False(t, found.Secure)
	require.Equal(t, http.SameSiteLaxMode, found.SameSite)
	require.Equal(t, 30*86400, found.MaxAge)
	require.Empty(t, found.Domain)
	require.Equal(t, "rt_testtoken", found.Value)
}

func TestRefreshCookieClearsWithMatchingAttributes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/logout", nil)
	c.Request.Host = "127.0.0.1:8080"
	clearRefreshCookie(c, &config.Config{})
	var found *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == refreshCookieName {
			found = ck
			break
		}
	}
	require.NotNil(t, found)
	require.Equal(t, "/api/v1/auth", found.Path)
	require.True(t, found.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, found.SameSite)
	require.Equal(t, 0, found.MaxAge)
	require.True(t, found.Expires.IsZero() || found.Expires.Unix() <= 0)
}

func TestAuthCookieOriginAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.Server.FrontendURL = "https://app.example.com"
	cfg.CORS.AllowedOrigins = []string{"https://extra.example.com"}

	t.Run("same origin", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "https://api.example.com/api/v1/auth/refresh", nil)
		c.Request.Host = "api.example.com"
		c.Request.Header.Set("Origin", "https://api.example.com")
		c.Request.Header.Set("X-Forwarded-Proto", "https")
		require.True(t, authCookieOriginAllowed(c, cfg))
	})
	t.Run("frontend url", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "https://api.example.com/api/v1/auth/refresh", nil)
		c.Request.Host = "api.example.com"
		c.Request.Header.Set("Origin", "https://app.example.com")
		c.Request.Header.Set("X-Forwarded-Proto", "https")
		require.True(t, authCookieOriginAllowed(c, cfg))
	})
	t.Run("referer fallback", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "https://api.example.com/api/v1/auth/refresh", nil)
		c.Request.Host = "api.example.com"
		c.Request.Header.Set("Referer", "https://extra.example.com/app")
		c.Request.Header.Set("X-Forwarded-Proto", "https")
		require.True(t, authCookieOriginAllowed(c, cfg))
	})
	t.Run("rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "https://api.example.com/api/v1/auth/refresh", nil)
		c.Request.Host = "api.example.com"
		c.Request.Header.Set("Origin", "https://evil.example")
		c.Request.Header.Set("X-Forwarded-Proto", "https")
		require.False(t, authCookieOriginAllowed(c, cfg))
	})
	t.Run("missing", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "https://api.example.com/api/v1/auth/refresh", nil)
		c.Request.Host = "api.example.com"
		require.False(t, authCookieOriginAllowed(c, cfg))
	})
}
