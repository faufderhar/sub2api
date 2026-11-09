package handler

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"

	"github.com/gin-gonic/gin"
)

const (
	refreshCookieName = "sub2api_refresh"
	refreshCookiePath = "/api/v1/auth"
)

var (
	errCSRFOriginRejected  = infraerrors.Forbidden("CSRF_ORIGIN_REJECTED", "请求来源不被允许")
	errRefreshTokenMissing = infraerrors.Unauthorized("REFRESH_TOKEN_MISSING", "refresh token cookie is missing")
)

func refreshCookieMaxAge(cfg *config.Config) int {
	days := 30
	if cfg != nil && cfg.JWT.RefreshTokenExpireDays > 0 {
		days = cfg.JWT.RefreshTokenExpireDays
	}
	return days * 86400
}

func refreshCookieSecure(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	host := c.Request.Host
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}
	hostname = strings.Trim(hostname, "[]")
	if (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1") && !isRequestHTTPS(c) {
		return false
	}
	return isRequestHTTPS(c)
}

func newRefreshCookie(c *gin.Context, cfg *config.Config, value string, maxAge int) *http.Cookie {
	cookie := &http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     refreshCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   refreshCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge > 0 {
		cookie.Expires = time.Now().Add(time.Duration(maxAge) * time.Second)
	} else {
		cookie.Expires = time.Unix(0, 0)
	}
	return cookie
}

func setRefreshCookie(c *gin.Context, cfg *config.Config, rawToken string) {
	if c == nil || strings.TrimSpace(rawToken) == "" {
		return
	}
	http.SetCookie(c.Writer, newRefreshCookie(c, cfg, rawToken, refreshCookieMaxAge(cfg)))
}

func clearRefreshCookie(c *gin.Context, cfg *config.Config) {
	if c == nil {
		return
	}
	http.SetCookie(c.Writer, newRefreshCookie(c, cfg, "", 0))
}

func readRefreshCookie(c *gin.Context) string {
	if c == nil {
		return ""
	}
	value, err := c.Cookie(refreshCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func originCandidate(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	if origin := strings.TrimSpace(c.GetHeader("Origin")); origin != "" {
		return origin
	}
	referer := strings.TrimSpace(c.GetHeader("Referer"))
	if referer == "" {
		return ""
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func requestOrigin(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	scheme := "http"
	if isRequestHTTPS(c) {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

func originMatches(candidate, allowed string) bool {
	candidate = strings.TrimRight(strings.TrimSpace(candidate), "/")
	allowed = strings.TrimRight(strings.TrimSpace(allowed), "/")
	if candidate == "" || allowed == "" {
		return false
	}
	cu, err1 := url.Parse(candidate)
	au, err2 := url.Parse(allowed)
	if err1 != nil || err2 != nil || cu.Host == "" || au.Host == "" {
		return strings.EqualFold(candidate, allowed)
	}
	return strings.EqualFold(cu.Scheme, au.Scheme) && strings.EqualFold(cu.Host, au.Host)
}

func authCookieOriginAllowed(c *gin.Context, cfg *config.Config) bool {
	candidate := originCandidate(c)
	if candidate == "" {
		return false
	}
	if originMatches(candidate, requestOrigin(c)) {
		return true
	}
	if cfg != nil {
		if originMatches(candidate, cfg.Server.FrontendURL) {
			return true
		}
		for _, allowed := range cfg.CORS.AllowedOrigins {
			if originMatches(candidate, allowed) {
				return true
			}
		}
	}
	return false
}

func ensureAuthCookieCSRF(c *gin.Context, cfg *config.Config) bool {
	if authCookieOriginAllowed(c, cfg) {
		return true
	}
	response.ErrorFrom(c, errCSRFOriginRejected)
	return false
}
