package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

type adminClaims struct {
	jwt.RegisteredClaims
	Generation string `json:"auth_generation,omitempty"`
}

func signAdminJWT(key []byte, generation string) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "ARTEX",
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Generation: generation,
	}).SignedString(key)
}

func parseAdminJWT(tokenStr string, key []byte) (adminClaims, error) {
	var claims adminClaims
	_, err := jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithSubject("ARTEX"), jwt.WithExpirationRequired())
	return claims, err
}

func (s *Server) readAdminCredentials(w http.ResponseWriter, r *http.Request) (db.AdminCredentials, bool) {
	if s.m != nil && s.m.pg != nil {
		if credentials, err := s.m.pg.GetAdminCredentials(r.Context()); err == nil {
			return credentials, true
		}
	}
	writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
	return db.AdminCredentials{}, false
}

// Check the signature before reading shared state. A missing generation on an
// upgraded installation matches its existing JWTs until the first rotation.
func (s *Server) authenticatedAdmin(w http.ResponseWriter, r *http.Request) (db.AdminCredentials, bool) {
	token := extractToken(r)
	if token == "" {
		writeProductError(w, 401, "unauthorized", "未授权", nil)
		return db.AdminCredentials{}, false
	}
	claims, err := parseAdminJWT(token, s.jwtKey)
	if err == nil {
		credentials, ok := s.readAdminCredentials(w, r)
		if !ok {
			return db.AdminCredentials{}, false
		}
		if claims.Generation == credentials.Generation {
			return credentials, true
		}
	}
	writeProductError(w, 401, "token_expired", "token 无效或已过期", nil)
	return db.AdminCredentials{}, false
}

// extractToken reads the JWT from Authorization: Bearer header,
// artex_token cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// requireAuth wraps h with JWT validation.
// /api/auth/*, /api/health and the Basic Auth gate check are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" || p == "/api/basic-auth/check" {
			h.ServeHTTP(w, r)
			return
		}
		if _, ok := s.authenticatedAdmin(w, r); !ok {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	credentials, ok := s.readAdminCredentials(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": credentials.PasswordHash != ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	credentials, ok := s.readAdminCredentials(w, r)
	if !ok {
		return
	}
	if credentials.PasswordHash != "" {
		writeProductError(w, 403, "password_already_set", "密码已设置", nil)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeProductError(w, 400, "password_required", "密码不能为空", nil)
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		code, params := passwordValidationCode(req.Password)
		writeProductError(w, 400, code, msg, params)
		return
	}
	s.replaceAdminPassword(w, r, credentials, req.Password)
}

func (s *Server) replaceAdminPassword(w http.ResponseWriter, r *http.Request, old db.AdminCredentials, password string) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		writeProductError(w, 500, "password_hash_failed", "密码加密失败", nil)
		return
	}
	next := db.AdminCredentials{PasswordHash: string(hash), Generation: rand.Text()}
	token, err := signAdminJWT(s.jwtKey, next.Generation)
	if err != nil {
		writeProductError(w, 500, "token_failed", "token 生成失败", nil)
		return
	}
	replaced, err := s.m.pg.ReplaceAdminCredentials(r.Context(), old, next)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if !replaced {
		if old.PasswordHash == "" {
			writeProductError(w, 403, "password_already_set", "密码已设置", nil)
		} else {
			writeProductError(w, 401, "token_expired", "token 无效或已过期", nil)
		}
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "token": token})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	credentials, ok := s.authenticatedAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeProductError(w, 400, "invalid_request", "请求格式错误", nil)
		return
	}
	if req.NewPassword == "" {
		writeProductError(w, 400, "new_password_required", "新密码不能为空", nil)
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		code, params := passwordValidationCode(req.NewPassword)
		writeProductError(w, 400, code, msg, params)
		return
	}
	if credentials.PasswordHash == "" {
		writeProductError(w, 403, "password_not_initialized", "密码未初始化，请先设置密码", nil)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(credentials.PasswordHash), []byte(req.OldPassword)); err != nil {
		writeProductError(w, 401, "current_password_incorrect", "当前密码错误", nil)
		return
	}
	s.replaceAdminPassword(w, r, credentials, req.NewPassword)
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeProductError(w, 400, "invalid_request", "请求格式错误", nil)
		return
	}
	if req.Username != "ARTEX" {
		writeProductError(w, 401, "invalid_credentials", "用户名或密码错误", nil)
		return
	}
	credentials, ok := s.readAdminCredentials(w, r)
	if !ok {
		return
	}
	if credentials.PasswordHash == "" {
		writeProductError(w, 403, "password_not_initialized", "密码未初始化，请先设置密码", nil)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(credentials.PasswordHash), []byte(req.Password)); err != nil {
		writeProductError(w, 401, "invalid_credentials", "用户名或密码错误", nil)
		return
	}
	tok, err := signAdminJWT(s.jwtKey, credentials.Generation)
	if err != nil {
		writeProductError(w, 500, "token_failed", "token 生成失败", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

func passwordValidationCode(password string) (string, map[string]any) {
	if utf8.RuneCountInString(password) < minPasswordRunes {
		return "password_too_short", map[string]any{"min": minPasswordRunes}
	}
	return "password_too_long", map[string]any{"max": maxPasswordBytes}
}
