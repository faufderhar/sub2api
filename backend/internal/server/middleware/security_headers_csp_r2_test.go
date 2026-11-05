//go:build unit

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func cspHeaderFor(t *testing.T, cfg config.CSPConfig) string {
	t.Helper()
	r := gin.New()
	r.Use(SecurityHeaders(cfg, nil))
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	csp := w.Header().Get("Content-Security-Policy")
	require.NotEmpty(t, csp)
	return csp
}

func cspDirective(policy, name string) []string {
	for _, raw := range strings.Split(policy, ";") {
		f := strings.Fields(raw)
		if len(f) > 0 && f[0] == name {
			return f[1:]
		}
	}
	return nil
}

// R2-CSP: the default header must not carry the old *.alicdn.com / *.stripe.com
// wildcards and must forbid plugins via object-src 'none'.
func TestR2CSP_DefaultPolicyNarrowed(t *testing.T) {
	for _, policy := range []string{"", config.DefaultCSPPolicy} {
		csp := cspHeaderFor(t, config.CSPConfig{Enabled: true, Policy: policy})
		require.NotContains(t, csp, "*.alicdn.com")
		require.NotContains(t, csp, "https://*.stripe.com")
		require.Equal(t, []string{"'none'"}, cspDirective(csp, "object-src"))

		script := cspDirective(csp, "script-src")
		for _, want := range []string{"https://o.alicdn.com", "https://g.alicdn.com", "https://x.alicdn.com", "https://js.stripe.com", "https://*.js.stripe.com"} {
			require.Contains(t, script, want)
		}
		require.NotContains(t, script, "https://hooks.stripe.com")
		frame := cspDirective(csp, "frame-src")
		for _, want := range []string{"https://js.stripe.com", "https://*.js.stripe.com", "https://hooks.stripe.com"} {
			require.Contains(t, frame, want)
		}
		// D1a: connect-src keeps https:.
		require.Contains(t, cspDirective(csp, "connect-src"), "https:")
	}
}

// requiredCSPDirectiveValues must not re-inject the broad Stripe wildcard.
func TestR2CSP_RequiredValuesNoStripeWildcard(t *testing.T) {
	for _, v := range requiredCSPDirectiveValues {
		require.NotEqual(t, "https://*.stripe.com", v.value, "directive %s", v.directive)
		require.NotContains(t, v.value, "*.alicdn.com")
	}
	enhanced := enhanceCSPPolicy("default-src 'self'")
	require.NotContains(t, enhanced, "https://*.stripe.com")
	require.Contains(t, cspDirective(enhanced, "frame-src"), "https://hooks.stripe.com")
	require.NotContains(t, cspDirective(enhanced, "script-src"), "https://hooks.stripe.com")
}

// A custom security.csp.policy still takes effect (only required values are appended).
func TestR2CSP_CustomPolicyStillApplies(t *testing.T) {
	custom := "default-src 'self'; script-src 'self' https://cdn.example.com; img-src 'self'; frame-ancestors 'self'"
	csp := cspHeaderFor(t, config.CSPConfig{Enabled: true, Policy: custom})
	require.Contains(t, cspDirective(csp, "script-src"), "https://cdn.example.com")
	require.Equal(t, []string{"'self'"}, cspDirective(csp, "img-src"))
	require.Equal(t, []string{"'self'"}, cspDirective(csp, "frame-ancestors"))
	require.NotContains(t, csp, "o.alicdn.com", "default policy must not leak into a custom policy")
	require.Nil(t, cspDirective(csp, "object-src"), "object-src is not forced onto a custom policy")
}
