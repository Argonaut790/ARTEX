package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestAdminCredentialsPostgresCompareAndSwap(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires an isolated ARTEX_PG_DSN")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	// Limit name resolution to temporary tables, even if the driver reconnects.
	cfg.RuntimeParams["search_path"] = "pg_temp"
	pool := stdlib.OpenDB(*cfg)
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	d := &DB{DB: pool}
	ctx := t.Context()
	if _, err := d.ExecContext(ctx, `CREATE TEMP TABLE settings (
		key text PRIMARY KEY, value text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal("could not create temporary settings table")
	}
	first := AdminCredentials{PasswordHash: "first-hash", Generation: "first-generation"}
	second := AdminCredentials{PasswordHash: "second-hash", Generation: "second-generation"}
	change := func(old, next AdminCredentials, want bool) {
		t.Helper()
		got, err := d.ReplaceAdminCredentials(ctx, old, next)
		if err != nil || got != want {
			t.Fatalf("compare-and-swap: replaced=%t, want %t, err=%v", got, want, err)
		}
	}
	change(AdminCredentials{}, first, true)
	change(AdminCredentials{}, second, false)
	change(first, second, true)
	change(first, first, false)
	change(AdminCredentials{PasswordHash: second.PasswordHash, Generation: first.Generation}, first, false)
	if got, err := d.GetAdminCredentials(ctx); err != nil || got != second {
		t.Fatal("stale writer changed the stored credentials")
	}
}

func TestSetSettingsAtomic(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	prefix := fmt.Sprintf("test.atomic_settings.%d", time.Now().UnixNano())
	defer func() { _, _ = d.Exec(`DELETE FROM settings WHERE key LIKE $1`, prefix+".%") }()
	values := map[string]string{prefix + ".worker_pools": "[]", prefix + ".workers": "3"}
	if err := d.SetSettingsAtomic(context.Background(), values); err != nil {
		t.Fatal(err)
	}
	for key, want := range values {
		got, ok, err := d.GetSetting(key)
		if err != nil || !ok || got != want {
			t.Fatalf("key %q: value=%q ok=%v err=%v, want %q", key, got, ok, err, want)
		}
	}
}
