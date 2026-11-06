package service

import (
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// ErrEncryptionKeyNotPersistent（M-5 第二轮）：加密密钥只是进程内临时 key（未设置 TOTP_ENCRYPTION_KEY，
// 且自动生成的 key 无法持久化到数据目录）。此时写入的长期密文在重启后无法解密，相关入口统一拒绝写入。
var ErrEncryptionKeyNotPersistent = infraerrors.BadRequest(
	"ENCRYPTION_KEY_NOT_PERSISTENT",
	"encryption key is not persistent (TOTP_ENCRYPTION_KEY is unset and the auto-generated key could not be saved to the data dir); "+
		"set TOTP_ENCRYPTION_KEY (64 hex chars) or make the data dir writable, then restart",
)
