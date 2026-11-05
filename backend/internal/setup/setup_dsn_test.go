package setup

import (
	"reflect"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func parseSetupDSN(t *testing.T, dsn string) map[string]string {
	t.Helper()
	c, err := pq.NewConnector(dsn)
	require.NoError(t, err)
	opts := reflect.ValueOf(c).Elem().FieldByName("opts")
	out := map[string]string{}
	iter := opts.MapRange()
	for iter.Next() {
		out[iter.Key().String()] = iter.Value().String()
	}
	return out
}

// 安装向导：空密码不再吞掉 dbname（之前生成 "password= dbname=x"，libpq 把 "dbname=x" 当成密码）。
func TestSetupDSN_EmptyPassword(t *testing.T) {
	cfg := &DatabaseConfig{Host: "127.0.0.1", Port: 5432, User: "postgres", Password: "", DBName: "sub2api", SSLMode: "disable"}
	opts := parseSetupDSN(t, buildPostgresDSN(cfg, cfg.DBName))
	require.Equal(t, "sub2api", opts["dbname"])
	require.Equal(t, "disable", opts["sslmode"])
	require.Empty(t, opts["password"])
}

func TestSetupDSN_PasswordWithSpacesAndQuotes(t *testing.T) {
	for _, pw := range []string{"has space", `q'uo"te`, `\ dbname=postgres`} {
		cfg := &DatabaseConfig{Host: "127.0.0.1", Port: 5432, User: "postgres", Password: pw, DBName: "sub2api", SSLMode: "disable"}
		opts := parseSetupDSN(t, buildPostgresDSN(cfg, postgresBootstrapDatabase))
		require.Equal(t, pw, opts["password"])
		require.Equal(t, postgresBootstrapDatabase, opts["dbname"])
	}
}
