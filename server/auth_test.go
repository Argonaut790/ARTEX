package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func authTestServer(t *testing.T, database string) *Server {
	t.Helper()
	pool, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	if _, err := pool.Exec(`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	return &Server{m: &Manager{pg: &db.DB{DB: pool}}, jwtKey: []byte("test-only-signing-key-32-characters")}
}

// Existing request fixtures use the exact claims that older releases issued.
func signJWT(key []byte) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "ARTEX", IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(jwtTTL)),
	}).SignedString(key)
}

func verifyJWT(token string, key []byte) bool {
	_, err := parseAdminJWT(token, key)
	return err == nil
}

func adminRequest(t *testing.T, h http.Handler, method, path, token, body string, want int) string {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: status %d, want %d", method, path, w.Code, want)
	}
	var result struct{ Token string }
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if want != 200 && result.Token != "" {
		t.Fatal("an unsuccessful request returned a token")
	}
	return result.Token
}

func TestAdminPasswordRotationAcrossInstances(t *testing.T) {
	file := filepath.Join(t.TempDir(), "settings.db")
	s := authTestServer(t, file)
	other := authTestServer(t, file)
	first, second := s.Handler(), other.Handler()
	initBody := `{"password":"fixture-password"}`
	login := `{"username":"ARTEX","password":"fixture-password"}`
	change := `{"old_password":"fixture-password","new_password":"replacement-password"}`
	initial := adminRequest(t, first, "POST", "/api/auth/init", "", initBody, 200)
	loginToken := adminRequest(t, second, "POST", "/api/auth/login", "", login, 200)
	adminRequest(t, second, "POST", "/api/auth/init", "", initBody, 403)
	adminRequest(t, first, "POST", "/api/auth/change-password", initial,
		`{"old_password":"wrong-password","new_password":"replacement-password"}`, 401)
	adminRequest(t, first, "GET", "/api/version", initial, "", 200)
	replacement := adminRequest(t, first, "POST", "/api/auth/change-password", initial, change, 200)
	adminRequest(t, second, "GET", "/api/version", loginToken, "", 401)
	adminRequest(t, second, "GET", "/api/version", replacement, "", 200)
	adminRequest(t, second, "POST", "/api/auth/change-password", initial,
		`{"old_password":"replacement-password","new_password":"another-password"}`, 401)
	adminRequest(t, first, "POST", "/api/auth/login", "", login, 401)
	if err := s.m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := other.m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := authTestServer(t, file).Handler()
	adminRequest(t, restarted, "GET", "/api/version", initial, "", 401)
	adminRequest(t, restarted, "GET", "/api/version", replacement, "", 200)
	fresh := adminRequest(t, restarted, "POST", "/api/auth/login", "",
		`{"username":"ARTEX","password":"replacement-password"}`, 200)
	adminRequest(t, restarted, "GET", "/api/version", fresh, "", 200)
}

func TestAdminLegacySessionUntilFirstRotation(t *testing.T) {
	s := authTestServer(t, ":memory:")
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec("INSERT INTO settings (key,value) VALUES ($1,$2)", db.AdminPasswordKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	adminRequest(t, h, "GET", "/api/version", token, "", 200)
	replacement := adminRequest(t, h, "POST", "/api/auth/change-password", token,
		`{"old_password":"legacy-password","new_password":"legacy-password"}`, 200)
	adminRequest(t, h, "GET", "/api/version", token, "", 401)
	adminRequest(t, h, "GET", "/api/version", replacement, "", 200)
}

func TestAdminRotationRollbackAndStaleGeneration(t *testing.T) {
	s := authTestServer(t, ":memory:")
	h := s.Handler()
	token := adminRequest(t, h, "POST", "/api/auth/init", "", `{"password":"fixture-password"}`, 200)
	before, err := s.m.pg.GetAdminCredentials(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a concurrent change after the caller read the password.
	stale := before
	stale.Generation = "earlier-generation"
	next := db.AdminCredentials{PasswordHash: "unused", Generation: "unused"}
	if replaced, err := s.m.pg.ReplaceAdminCredentials(t.Context(), stale, next); err != nil || replaced {
		t.Fatalf("stale compare-and-swap: replaced=%t err=%v", replaced, err)
	}
	if _, err := s.m.pg.Exec(`CREATE TRIGGER fail_rotation BEFORE UPDATE ON settings
		WHEN OLD.key = 'auth.session_generation' BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	adminRequest(t, h, "POST", "/api/auth/change-password", token,
		`{"old_password":"fixture-password","new_password":"replacement-password"}`, 503)
	after, err := s.m.pg.GetAdminCredentials(t.Context())
	if err != nil || before != after {
		t.Fatal("failed rotation changed persisted credentials")
	}
	adminRequest(t, h, "GET", "/api/version", token, "", 200)
	if err := s.m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	adminRequest(t, h, "GET", "/api/version", token, "", 503)
	adminRequest(t, h, "GET", "/api/version", "malformed", "", 401)
	adminRequest(t, h, "POST", "/api/auth/change-password", token, "{}", 503)
	adminRequest(t, h, "POST", "/api/auth/login", "", `{"username":"ARTEX","password":"fixture-password"}`, 503)
}

// GetSetting 对"键不存在"和"读取出错"的返回值只差一个 error：两种情况 value 都是
// 空串。密码相关的 handler 一旦把 error 当成"还没设置密码"，就会在数据库抖动期间
// 敞开初始化入口——authInit 会放行一个未认证请求去覆盖已有的管理员密码，
// authStatus 则会把前端直接送到 /setup 去照着做这件事。
//
// 这两个测试把 handler 的连接池关掉来制造读取失败，断言两处都 fail closed。
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	s := authTestServer(t, ":memory:")
	// 关掉池子，让后续 GetSetting 返回 error 而不是 sql.ErrNoRows。
	if err := s.m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败被当成未初始化会把用户送去 /setup 覆盖密码); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("读失败时不应回答 initialized，得到 %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	s := authTestServer(t, ":memory:")
	if err := s.m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败时放行会让未认证请求覆盖已有密码); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("读失败时不应签发 token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"空", "", true},
		{"七位", "1234567", true},
		{"八位", "12345678", false},
		{"八个汉字按字符数而非字节数计", "密码密码密码密码", false},
		{"三个汉字够 9 字节但只有 3 个字符", "密码强", true},
		{"72 字节", strings.Repeat("a", 72), false},
		{"73 字节超出 bcrypt 上限", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}
