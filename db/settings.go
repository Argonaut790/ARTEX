package db

import (
	"context"
	"database/sql"
	"errors"
	"sort"
)

const (
	AdminPasswordKey   = "auth.password_hash"
	adminGenerationKey = "auth.session_generation"
)

type AdminCredentials struct {
	PasswordHash string
	Generation   string // Empty only for installations without a generation row.
}

// GetAdminCredentials reads the hash and generation from the same SQL snapshot.
func (d *DB) GetAdminCredentials(ctx context.Context) (AdminCredentials, error) {
	var hash, generation sql.NullString
	err := d.QueryRowContext(ctx, `SELECT
		(SELECT value FROM settings WHERE key=$1),
		(SELECT value FROM settings WHERE key=$2)`, AdminPasswordKey, adminGenerationKey).Scan(&hash, &generation)
	if err != nil {
		return AdminCredentials{}, err
	}
	if (hash.Valid && hash.String == "") || (generation.Valid && generation.String == "") {
		return AdminCredentials{}, errors.New("empty admin credential setting")
	}
	return AdminCredentials{PasswordHash: hash.String, Generation: generation.String}, nil
}

// ReplaceAdminCredentials commits both settings only if each old value still
// matches. Always lock the password row first, including in reset-password.sh.
func (d *DB) ReplaceAdminCredentials(ctx context.Context, old, next AdminCredentials) (bool, error) {
	if next.PasswordHash == "" || next.Generation == "" {
		return false, errors.New("incomplete admin credentials")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	for _, setting := range []struct{ key, old, next string }{
		{AdminPasswordKey, old.PasswordHash, next.PasswordHash},
		{adminGenerationKey, old.Generation, next.Generation},
	} {
		var res sql.Result
		if setting.old == "" {
			res, err = tx.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES ($1, $2)
				ON CONFLICT (key) DO NOTHING`, setting.key, setting.next)
		} else {
			res, err = tx.ExecContext(ctx, `UPDATE settings SET value=$1, updated_at=CURRENT_TIMESTAMP
				WHERE key=$2 AND value=$3`, setting.next, setting.key, setting.old)
		}
		if err != nil {
			return false, err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// Settings is a tiny key-value store for global app config the UI toggles at
// runtime (e.g. traffic_capture). Missing keys fall back to caller defaults.

// GetSetting returns the stored value and ok=false when the key is unset.
func (d *DB) GetSetting(key string) (value string, ok bool, err error) {
	err = d.QueryRow(`SELECT value FROM settings WHERE key=$1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetSetting upserts a setting value.
func (d *DB) SetSetting(key, value string) error {
	return d.SetSettingContext(context.Background(), key, value)
}

// SetSettingContext upserts a setting and respects cancellation or a deadline.
func (d *DB) SetSettingContext(ctx context.Context, key, value string) error {
	_, err := d.ExecContext(ctx, `
INSERT INTO settings(key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, value)
	return err
}

// SetSettingsAtomic upserts several settings in one transaction. Keys are
// sorted so concurrent callers acquire row locks in a deterministic order.
func (d *DB) SetSettingsAtomic(ctx context.Context, values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // commit makes this a no-op
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO settings(key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, values[key]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertSettingIfAbsent 只在 key 尚未存在时写入，已存在则原样保留并返回 inserted=false。
// 给 auth.password_hash 这类"只允许首次设置"的键用：判定落在数据库的主键约束上，
// 调用方先 GetSetting 再写的那种检查就只是快速失败路径——读出错或并发撞车时，
// 已有的值也不会被 ON CONFLICT DO UPDATE 顺手覆盖掉。
func (d *DB) InsertSettingIfAbsent(key, value string) (inserted bool, err error) {
	res, err := d.Exec(`
INSERT INTO settings(key, value) VALUES ($1, $2)
ON CONFLICT (key) DO NOTHING`, key, value)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetBool returns the boolean setting, or def when unset/unparseable.
func (d *DB) GetBool(key string, def bool) bool {
	v, ok, err := d.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	return v == "true" || v == "1"
}

// SetBool stores a boolean setting as "true"/"false".
func (d *DB) SetBool(key string, val bool) error {
	if val {
		return d.SetSetting(key, "true")
	}
	return d.SetSetting(key, "false")
}
