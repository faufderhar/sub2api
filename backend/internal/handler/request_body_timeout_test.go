//go:build unit

package handler

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestIsRequestBodyReadTimeout(t *testing.T) {
	require.False(t, isRequestBodyReadTimeout(nil))
	require.False(t, isRequestBodyReadTimeout(errors.New("unexpected EOF")))
	require.True(t, isRequestBodyReadTimeout(os.ErrDeadlineExceeded))
	require.True(t, isRequestBodyReadTimeout(timeoutNetError{}))
	var ne net.Error = timeoutNetError{}
	require.True(t, isRequestBodyReadTimeout(ne))
}

func TestApplyRequestBodyReadTimeoutSetsConnectionClose(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	require.False(t, applyRequestBodyReadTimeout(c, errors.New("parse")))
	require.Empty(t, rec.Header().Get("Connection"))

	require.True(t, applyRequestBodyReadTimeout(c, os.ErrDeadlineExceeded))
	require.Equal(t, "close", rec.Header().Get("Connection"))
}

func TestRequestBodyReadTimeoutConstants(t *testing.T) {
	require.Equal(t, http.StatusRequestTimeout, 408)
	require.Equal(t, "REQUEST_BODY_TIMEOUT", requestBodyReadTimeoutType)
	require.Equal(t, "Request body read timed out", requestBodyReadTimeoutMessage)
}
