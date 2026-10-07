package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"waf/internal/backup"
	"waf/internal/config"
	"waf/internal/guard"
	"waf/internal/policy"
	"waf/internal/proxy"
	"waf/internal/secure"
	"waf/internal/store"
	"waf/internal/tlsmgr"
	"waf/web"
)

type Handler struct {
	boot                config.Bootstrap
	store               *store.Store
	engine              *proxy.Engine
	certs               *tlsmgr.Manager
	mux                 *http.ServeMux
	limits              *guard.Limits
	authSlots           chan struct{}
	requestSlots        chan struct{}
	backupMu            sync.Mutex
	adminCIDRs, trusted []netip.Prefix
}
type sessionKey struct{}

func New(boot config.Bootstrap, s *store.Store, e *proxy.Engine, certs *tlsmgr.Manager) *Handler {
	a := &Handler{boot: boot, store: s, engine: e, certs: certs, mux: http.NewServeMux(), limits: guard.NewLimits(10000), authSlots: make(chan struct{}, 2), requestSlots: make(chan struct{}, 32), adminCIDRs: guard.ParseCIDRs(boot.AdminCIDRs), trusted: guard.ParseCIDRs(boot.TrustedProxies)}
	a.mux.HandleFunc("POST /api/v1/auth/login", a.login)
	a.route("GET /api/v1/auth/session", "viewer", a.session)
	a.route("POST /api/v1/auth/logout", "viewer", a.logout)
	a.route("GET /api/v1/overview", "viewer", a.overview)
	a.route("GET /api/v1/config/active", "viewer", a.active)
	a.route("GET /api/v1/config/draft", "viewer", a.draft)
	a.route("PUT /api/v1/config/draft", "operator", a.saveDraft)
	a.route("POST /api/v1/config/validate", "operator", a.validate)
	a.route("POST /api/v1/config/publish", "operator", a.publish)
	a.route("POST /api/v1/config/rollback", "operator", a.rollback)
	a.route("GET /api/v1/config/revisions", "viewer", a.revisions)
	a.route("GET /api/v1/rules/catalog", "viewer", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"version": policy.CRSVersion, "rules": policy.Catalog()})
	})
	a.route("POST /api/v1/rules/evaluate", "operator", a.evaluate)
	a.route("GET /api/v1/certificates", "viewer", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, a.certs.Statuses()) })
	a.route("GET /api/v1/credentials", "admin", a.credentials)
	a.route("PUT /api/v1/credentials/{name}", "admin", a.putCredential)
	a.route("GET /api/v1/users", "admin", a.users)
	a.route("POST /api/v1/users", "admin", a.createUser)
	a.route("PATCH /api/v1/users/{id}", "admin", a.updateUser)
	a.route("GET /api/v1/events", "viewer", a.events)
	a.route("GET /api/v1/audit", "viewer", a.audit)
	a.route("GET /api/v1/backups", "admin", a.backups)
	a.route("POST /api/v1/backups", "admin", a.createBackup)
	a.route("GET /api/v1/backups/{name}", "admin", a.downloadBackup)
	a.route("GET /api/v1/openapi.json", "viewer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAPI)
	})
	a.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "not_found") })
	a.mux.Handle("/", web.Handler())
	return a
}
func (a *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case a.requestSlots <- struct{}{}:
		defer func() { <-a.requestSlots }()
	default:
		fail(w, 503, "admin_busy")
		return
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(10 * time.Second))
	rc.SetWriteDeadline(time.Now().Add(3 * time.Minute))
	defer rc.SetReadDeadline(time.Time{})
	defer rc.SetWriteDeadline(time.Time{})
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.TLS == nil && !a.boot.Development {
		fail(w, 403, "https_required")
		return
	}
	ip := guard.ClientIP(r, a.trusted)
	if len(a.adminCIDRs) > 0 && !guard.InCIDRs(ip, a.adminCIDRs) {
		fail(w, 403, "access_denied")
		return
	}
	if !a.limits.Allow("all:"+ip.String(), 10, 60, 0) {
		fail(w, 429, "rate_limited")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
	}
	a.mux.ServeHTTP(w, r)
}
func (a *Handler) route(pattern, role string, h http.HandlerFunc) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		cookie, e := r.Cookie(a.cookieName())
		if e != nil {
			fail(w, 401, "authentication_required")
			return
		}
		session, e := a.store.Session(cookie.Value)
		if e != nil {
			fail(w, 401, "session_expired")
			return
		}
		rank := map[string]int{"viewer": 0, "operator": 1, "admin": 2}
		if rank[session.User.Role] < rank[role] {
			fail(w, 403, "permission_denied")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if !a.sameOrigin(r) || !secure.Equal(session.CSRF, r.Header.Get("X-CSRF-Token")) {
				fail(w, 403, "csrf_validation_failed")
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
	})
}
func (a *Handler) sameOrigin(r *http.Request) bool {
	scheme := "https"
	if a.boot.Development {
		scheme = "http"
	}
	return r.Header.Get("Origin") == scheme+"://"+r.Host
}
func actor(r *http.Request) string {
	return r.Context().Value(sessionKey{}).(store.Session).User.Username
}
func (a *Handler) cookieName() string {
	if a.boot.Development {
		return "waf_session_dev"
	}
	return "__Host-waf_session"
}
func (a *Handler) login(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		fail(w, 403, "invalid_origin")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !decode(w, r, &body) {
		return
	}
	if !config.ValidID(body.Username) || len(body.Password) > 256 || len(body.Code) > 64 {
		fail(w, 401, "invalid_credentials_or_mfa")
		return
	}
	ip := guard.ClientIP(r, a.trusted).String()
	if !a.limits.Allow("login-ip:"+ip, .2, 5, time.Minute) || !a.limits.Allow("login-user:"+body.Username, .1, 5, time.Minute) {
		fail(w, 429, "login_rate_limited")
		return
	}
	select {
	case a.authSlots <- struct{}{}:
		defer func() { <-a.authSlots }()
	default:
		fail(w, 429, "login_busy")
		return
	}
	u, e := a.store.Authenticate(body.Username, body.Password, body.Code, a.boot.Development)
	if e != nil {
		a.store.Audit("anonymous", "auth.failure", "source="+ip)
		fail(w, 401, "invalid_credentials_or_mfa")
		return
	}
	token, csrf, e := a.store.NewSession(u)
	if e != nil {
		internal(w, e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: token, Path: "/", HttpOnly: true, Secure: !a.boot.Development, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	respond(w, 200, map[string]any{"user": u, "csrf_token": csrf, "development": a.boot.Development})
}
func (a *Handler) session(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessionKey{}).(store.Session)
	respond(w, 200, map[string]any{"user": s.User, "csrf_token": s.CSRF, "expires": s.Expires, "development": a.boot.Development})
}
func (a *Handler) logout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(a.cookieName())
	if e := a.store.DeleteSession(cookie.Value); e != nil {
		internal(w, e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: "", Path: "/", HttpOnly: true, Secure: !a.boot.Development, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	respond(w, 200, map[string]bool{"ok": true})
}
func (a *Handler) overview(w http.ResponseWriter, r *http.Request) {
	stats, e := a.store.Stats()
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, map[string]any{"stats": stats, "revision": a.engine.Revision(), "crs_version": policy.CRSVersion, "upstreams": a.engine.UpstreamStatus(), "certificates": a.certs.Statuses(), "development": a.boot.Development})
}
func (a *Handler) active(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Active()
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, v)
}
func (a *Handler) draft(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Draft()
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, v)
}
func (a *Handler) saveDraft(w http.ResponseWriter, r *http.Request) {
	var d store.Draft
	if !decode(w, r, &d) {
		return
	}
	if e := d.Bundle.NormalizeAndValidate(a.boot); e != nil {
		fail(w, 400, e.Error())
		return
	}
	saved, e := a.store.SaveDraft(d, actor(r))
	if e != nil {
		storageError(w, e)
		return
	}
	respond(w, 200, saved)
}
func (a *Handler) validate(w http.ResponseWriter, r *http.Request) {
	var b config.Bundle
	if !decode(w, r, &b) {
		return
	}
	if !a.engine.PublishMu.TryLock() {
		fail(w, 409, "another_validation_or_publish_is_running")
		return
	}
	defer a.engine.PublishMu.Unlock()
	compiled, e := a.engine.Compile(b)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	defer compiled.Release()
	if e = a.certs.Validate(compiled.Bundle); e != nil {
		fail(w, 400, e.Error())
		return
	}
	respond(w, 200, map[string]any{"valid": true, "crs_version": policy.CRSVersion, "bundle": compiled.Bundle})
}
func (a *Handler) publish(w http.ResponseWriter, r *http.Request) {
	var expected struct {
		Version      int64 `json:"version"`
		BaseRevision int64 `json:"base_revision"`
	}
	if !decode(w, r, &expected) {
		return
	}
	if !a.engine.PublishMu.TryLock() {
		fail(w, 409, "another_validation_or_publish_is_running")
		return
	}
	defer a.engine.PublishMu.Unlock()
	d, e := a.store.Draft()
	if e != nil {
		internal(w, e)
		return
	}
	if d.Version != expected.Version || d.BaseRevision != expected.BaseRevision {
		fail(w, 409, store.ErrConflict.Error())
		return
	}
	a.publishDraft(w, r, d)
}
func (a *Handler) publishDraft(w http.ResponseWriter, r *http.Request, d store.Draft) {
	compiled, e := a.engine.Compile(d.Bundle)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if e = a.certs.Validate(compiled.Bundle); e != nil {
		compiled.Release()
		fail(w, 400, e.Error())
		return
	}
	d.Bundle = compiled.Bundle
	revision, e := a.store.Publish(d, actor(r), policy.CRSVersion)
	if e != nil {
		compiled.Release()
		storageError(w, e)
		return
	}
	a.engine.Activate(compiled, revision.ID)
	if e = a.certs.Sync(revision.Bundle); e != nil {
		slog.Error("certificate synchronization failed", "revision", revision.ID, "error", e)
		respond(w, 200, map[string]any{"revision": revision.ID, "warning": "Configuration published; certificate automation needs attention."})
		return
	}
	respond(w, 200, map[string]any{"revision": revision.ID})
}
func (a *Handler) rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Revision     int64 `json:"revision"`
		Version      int64 `json:"version"`
		BaseRevision int64 `json:"base_revision"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !a.engine.PublishMu.TryLock() {
		fail(w, 409, "another_validation_or_publish_is_running")
		return
	}
	defer a.engine.PublishMu.Unlock()
	target, e := a.store.Revision(body.Revision)
	if e != nil {
		storageError(w, e)
		return
	}
	d := store.Draft{Version: body.Version, BaseRevision: body.BaseRevision, Bundle: target.Bundle}
	if e = d.Bundle.NormalizeAndValidate(a.boot); e != nil {
		fail(w, 400, e.Error())
		return
	}
	d, e = a.store.SaveDraft(d, actor(r))
	if e != nil {
		storageError(w, e)
		return
	}
	a.publishDraft(w, r, d)
}
func (a *Handler) revisions(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Revisions()
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, v)
}
func (a *Handler) evaluate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Expression string         `json:"expression"`
		Scope      config.Scope   `json:"scope"`
		Sample     map[string]any `json:"sample"`
	}
	if !decode(w, r, &b) {
		return
	}
	match, e := a.engine.ValidateExpression(b.Expression, b.Scope, b.Sample)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	respond(w, 200, map[string]any{"valid": true, "matches": match})
}
func (a *Handler) credentials(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Secrets()
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, v)
}
func (a *Handler) putCredential(w http.ResponseWriter, r *http.Request) {
	var c tlsmgr.Credential
	if !decode(w, r, &c) {
		return
	}
	raw, _ := json.Marshal(c)
	if _, e := tlsmgr.ParseCredential(raw); e != nil {
		fail(w, 400, e.Error())
		return
	}
	a.engine.PublishMu.Lock()
	defer a.engine.PublishMu.Unlock()
	if e := a.store.PutSecret(r.PathValue("name"), raw, actor(r)); e != nil {
		storageError(w, e)
		return
	}
	rev, e := a.store.Active()
	if e == nil {
		e = a.certs.Sync(rev.Bundle)
	}
	if e != nil {
		respond(w, 200, map[string]any{"ok": true, "warning": "Credential saved; certificate automation needs attention."})
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (a *Handler) users(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Users()
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, v)
}
func (a *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &b) {
		return
	}
	u, secret, codes, e := a.store.CreateUser(b.Username, b.Password, b.Role, actor(r))
	if e != nil {
		fail(w, 400, "user_creation_failed: check username, role and password length")
		return
	}
	otp := "otpauth://totp/" + url.PathEscape("WAF:"+u.Username) + "?secret=" + secret + "&issuer=WAF&algorithm=SHA1&digits=6&period=30"
	respond(w, 201, map[string]any{"user": u, "totp_secret": secret, "otpauth_url": otp, "recovery_codes": codes})
}
func (a *Handler) updateUser(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	}
	if !decode(w, r, &b) {
		return
	}
	if e := a.store.UpdateUser(r.PathValue("id"), b.Role, b.Disabled, actor(r)); e != nil {
		fail(w, 400, e.Error())
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (a *Handler) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	v, e := a.store.Events(store.EventFilter{SiteID: q.Get("site_id"), Action: q.Get("action"), Before: before, Limit: limit})
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, v)
}
func (a *Handler) audit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	v, e := a.store.Audits(before)
	if e != nil {
		internal(w, e)
		return
	}
	respond(w, 200, v)
}
func (a *Handler) backups(w http.ResponseWriter, r *http.Request) {
	entries, e := os.ReadDir(filepath.Join(a.boot.DataDir, "backups"))
	if e != nil && !os.IsNotExist(e) {
		internal(w, e)
		return
	}
	out := []map[string]any{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".age") {
			continue
		}
		info, e := entry.Info()
		if e == nil {
			out = append(out, map[string]any{"name": entry.Name(), "size": info.Size(), "created": info.ModTime().UTC()})
		}
	}
	respond(w, 200, out)
}
func (a *Handler) createBackup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Password) < 12 || len(b.Password) > 256 {
		fail(w, 400, "backup_password_must_be_12_to_256_bytes")
		return
	}
	if !a.backupMu.TryLock() {
		fail(w, 409, "backup_already_running")
		return
	}
	defer a.backupMu.Unlock()
	dir := filepath.Join(a.boot.DataDir, "backups")
	if e := os.MkdirAll(dir, 0700); e != nil {
		internal(w, e)
		return
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) >= 10 {
		fail(w, 409, "backup_limit_reached: archive or remove old backups using the local CLI")
		return
	}
	name := "waf-" + time.Now().UTC().Format("20060102T150405") + "-" + secure.Random(4) + ".age"
	p := filepath.Join(dir, name)
	f, e := os.OpenFile(p+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		internal(w, e)
		return
	}
	e = backup.Create(a.boot, a.store, b.Password, f)
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		os.Remove(p + ".tmp")
		internal(w, e)
		return
	}
	if e = os.Rename(p+".tmp", p); e != nil {
		internal(w, e)
		return
	}
	if e = a.store.Audit(actor(r), "backup.create", name); e != nil {
		internal(w, e)
		return
	}
	respond(w, 201, map[string]string{"name": name})
}
func (a *Handler) downloadBackup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if filepath.Base(name) != name || !strings.HasPrefix(name, "waf-") || !strings.HasSuffix(name, ".age") {
		fail(w, 400, "invalid_backup_name")
		return
	}
	p := filepath.Join(a.boot.DataDir, "backups", name)
	if _, e := os.Stat(p); e != nil {
		fail(w, 404, "backup_not_found")
		return
	}
	if e := a.store.Audit(actor(r), "backup.download", name); e != nil {
		internal(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, p)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "application_json_required")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid_json: "+e.Error())
		return false
	}
	if e := d.Decode(new(any)); e != io.EOF {
		fail(w, 400, "exactly_one_json_object_required")
		return false
	}
	return true
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
func internal(w http.ResponseWriter, e error) {
	slog.Error("administration request failed", "error", e)
	fail(w, 500, "internal_error")
}
func storageError(w http.ResponseWriter, e error) {
	if errors.Is(e, config.ErrUnsupportedConfiguration) {
		fail(w, 400, e.Error())
	} else if errors.Is(e, store.ErrConflict) {
		fail(w, 409, e.Error())
	} else if errors.Is(e, sql.ErrNoRows) {
		fail(w, 404, "not_found")
	} else {
		internal(w, e)
	}
}
