package config

import (
	"strconv"
	"strings"
)

// QuotePostgresDSNValue 按 libpq key/value 连接串规则给值加单引号：反斜杠和单引号用反斜杠转义。
// 加引号后空值（空密码）、含空格或引号的值都不会吞掉后面的参数（如 dbname）。
func QuotePostgresDSNValue(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('\'')
	for _, r := range value {
		if r == '\\' || r == '\'' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// PostgresDSNParam 是 key/value 连接串中的一项。
type PostgresDSNParam struct {
	Key   string
	Value string
}

// postgresDSNValueNeedsQuote 报告值是否必须加引号：空值、含空白、单引号或反斜杠。
// 其它值保持原样输出，常规配置生成的连接串与历史格式一致。
func postgresDSNValueNeedsQuote(value string) bool {
	if value == "" {
		return true
	}
	return strings.ContainsAny(value, " \t\n\r\v\f'\\")
}

// BuildPostgresKeywordDSN 用 libpq key/value 格式拼接连接串；空值或含空白/引号/反斜杠的值加引号转义。
func BuildPostgresKeywordDSN(params ...PostgresDSNParam) string {
	parts := make([]string, 0, len(params))
	for _, p := range params {
		value := p.Value
		if postgresDSNValueNeedsQuote(value) {
			value = QuotePostgresDSNValue(value)
		}
		parts = append(parts, p.Key+"="+value)
	}
	return strings.Join(parts, " ")
}

// BuildPostgresDSN 构造标准连接串。password 为空时省略该项（与历史行为一致）。
func BuildPostgresDSN(host string, port int, user, password, dbName, sslMode string, extra ...PostgresDSNParam) string {
	params := []PostgresDSNParam{
		{"host", host},
		{"port", strconv.Itoa(port)},
		{"user", user},
	}
	if password != "" {
		params = append(params, PostgresDSNParam{"password", password})
	}
	params = append(params, PostgresDSNParam{"dbname", dbName}, PostgresDSNParam{"sslmode", sslMode})
	params = append(params, extra...)
	return BuildPostgresKeywordDSN(params...)
}
