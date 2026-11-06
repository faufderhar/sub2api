package config

import (
	"reflect"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// parsePQ 用 lib/pq 自己的解析器解析连接串，返回解析后的参数。
func parsePQ(t *testing.T, dsn string) map[string]string {
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

func TestDSN_EmptyPasswordDoesNotSwallowDBName(t *testing.T) {
	// setup 场景：总是带 password 项。
	dsn := BuildPostgresKeywordDSN(PostgresDSNParam{"host", "db"}, PostgresDSNParam{"password", ""}, PostgresDSNParam{"dbname", "sub2api"}, PostgresDSNParam{"sslmode", "disable"})
	opts := parsePQ(t, dsn)
	require.Equal(t, "", opts["password"])
	require.Equal(t, "sub2api", opts["dbname"])
	require.Equal(t, "disable", opts["sslmode"])

	d := DatabaseConfig{Host: "db", Port: 5432, User: "u", DBName: "sub2api", SSLMode: "disable"}
	opts = parsePQ(t, d.DSNWithTimezone("UTC"))
	require.NotContains(t, opts, "password")
	require.Equal(t, "sub2api", opts["dbname"])
	require.Equal(t, "UTC", opts["TimeZone"])
}

func TestDSN_PasswordWithSpacesAndQuotes(t *testing.T) {
	for _, pw := range []string{"p w d", `it's "quoted"`, `back\slash' dbname=evil`, " lead", "trail ", "="} {
		d := DatabaseConfig{Host: "db.local", Port: 6543, User: "my user", Password: pw, DBName: "sub2api", SSLMode: "require"}
		for _, dsn := range []string{d.DSN(), d.DSNWithTimezone("Asia/Shanghai")} {
			opts := parsePQ(t, dsn)
			require.Equal(t, pw, opts["password"], dsn)
			require.Equal(t, "sub2api", opts["dbname"], dsn)
			require.Equal(t, "my user", opts["user"])
			require.Equal(t, "6543", opts["port"])
			require.Equal(t, "require", opts["sslmode"])
		}
	}
}

func TestQuotePostgresDSNValue(t *testing.T) {
	require.Equal(t, `''`, QuotePostgresDSNValue(""))
	require.Equal(t, `'a\'b\\c'`, QuotePostgresDSNValue(`a'b\c`))
}

func TestDSN_PlainValuesKeepHistoricalFormat(t *testing.T) {
	d := DatabaseConfig{Host: "localhost", Port: 5432, User: "u", Password: "p", DBName: "db", SSLMode: "prefer"}
	require.Equal(t, "host=localhost port=5432 user=u password=p dbname=db sslmode=prefer", d.DSN())
	require.Equal(t, "host=localhost port=5432 user=u password='p w' dbname=db sslmode=prefer", (&DatabaseConfig{Host: "localhost", Port: 5432, User: "u", Password: "p w", DBName: "db", SSLMode: "prefer"}).DSN())
}
