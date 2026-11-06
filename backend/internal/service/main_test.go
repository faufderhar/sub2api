package service

import (
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestMain sets gin's global mode once before any test runs (L-12). gin v1.9 stores the
// mode in a plain global, so calling gin.SetMode inside parallel tests is a data race.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}
