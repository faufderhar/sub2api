package httputil

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type endlessReader struct{ n int64 }

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	r.n += int64(len(p))
	return len(p), nil
}

func TestReadResponseBody_Limits(t *testing.T) {
	body, err := ReadResponseBody(bytes.NewReader(bytes.Repeat([]byte("x"), 16)), 16)
	require.NoError(t, err)
	require.Len(t, body, 16)

	body, err = ReadResponseBody(bytes.NewReader(bytes.Repeat([]byte("x"), 17)), 16)
	require.ErrorIs(t, err, ErrResponseBodyTooLarge)
	require.Len(t, body, 16, "overflow returns the truncated prefix")

	_, err = ReadResponseBody(nil, 16)
	require.Error(t, err)
}

// An endless upstream body must not be buffered without bound.
func TestReadResponseBody_EndlessBodyStopsAtLimit(t *testing.T) {
	r := &endlessReader{}
	_, err := ReadResponseBody(r, 1<<20)
	require.True(t, errors.Is(err, ErrResponseBodyTooLarge))
	require.Less(t, r.n, int64(2<<20), "reader consumed far beyond the limit")
}

// TestNoBareReadAllOnResponseBody is the M-6 guard: upstream/gateway code must
// read HTTP response bodies through ReadResponseBody (or another LimitReader),
// never with a bare io.ReadAll(x.Body).
func TestNoBareReadAllOnResponseBody(t *testing.T) {
	root := filepath.Join("..", "..") // backend/internal
	bare := regexp.MustCompile(`io\.ReadAll\(\s*[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\.Body\s*\)`)
	allowed := map[string]bool{
		// Request bodies (bounded by the ingress body limits), not upstream responses.
		"io.ReadAll(c.Request.Body)": true,
	}
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, m := range bare.FindAllString(line, -1) {
				if !allowed[m] {
					offenders = append(offenders, path+":"+itoa(i+1)+": "+m)
				}
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, offenders, "use httputil.ReadResponseBody(resp.Body, limit) instead of a bare io.ReadAll")
}

func itoa(i int) string {
	var b [20]byte
	n := len(b)
	for {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
		if i == 0 {
			break
		}
	}
	return string(b[n:])
}
