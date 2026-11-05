//go:build unit

package repository

import (
	"bytes"
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/httputil"
	"github.com/stretchr/testify/require"
)

// M-6：Upload(io.Reader) 有界读入内存，超限报错且不调用 S3。
func TestM6_S3UploadBoundedRead(t *testing.T) {
	old := s3InMemoryUploadMaxBytes
	s3InMemoryUploadMaxBytes = 8
	t.Cleanup(func() { s3InMemoryUploadMaxBytes = old })

	store := &S3BackupStore{bucket: "b"} // client 为 nil：超限必须在调用 S3 之前返回
	_, err := store.Upload(context.Background(), "k", bytes.NewReader(make([]byte, 9)), "application/gzip")
	require.ErrorIs(t, err, httputil.ErrResponseBodyTooLarge)
}
