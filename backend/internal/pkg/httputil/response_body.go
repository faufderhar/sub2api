package httputil

import (
	"errors"
	"fmt"
	"io"
)

// ErrResponseBodyTooLarge is returned by ReadResponseBody when the body is larger
// than the allowed limit.
var ErrResponseBodyTooLarge = errors.New("response body too large")

const (
	// DefaultResponseBodyMaxBytes bounds non-streaming upstream response bodies
	// when no configured limit is available. It mirrors
	// config.DefaultUpstreamResponseReadMaxBytes (128 MiB).
	DefaultResponseBodyMaxBytes int64 = 128 << 20
	// SmallResponseBodyMaxBytes bounds small control-plane responses
	// (OAuth token/userinfo, checksum files, usage probes, error bodies).
	SmallResponseBodyMaxBytes int64 = 8 << 20
)

// ReadResponseBody reads at most maxBytes from r (M-6). It reads maxBytes+1
// bytes through an io.LimitReader so a body exactly at the limit is accepted
// and anything larger is reported with ErrResponseBodyTooLarge instead of
// being buffered without bound.
//
// On overflow the first maxBytes bytes are returned together with the error,
// so callers that only log an error body can keep using the truncated prefix.
// maxBytes <= 0 falls back to DefaultResponseBodyMaxBytes.
//
// Do not use a bare io.ReadAll(resp.Body) for upstream responses; a source
// scan test (TestNoBareReadAllOnResponseBody) rejects new occurrences.
func ReadResponseBody(r io.Reader, maxBytes int64) ([]byte, error) {
	if r == nil {
		return nil, errors.New("response body is nil")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultResponseBodyMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return body, err
	}
	if int64(len(body)) > maxBytes {
		return body[:maxBytes], fmt.Errorf("%w: limit=%d bytes", ErrResponseBodyTooLarge, maxBytes)
	}
	return body, nil
}
