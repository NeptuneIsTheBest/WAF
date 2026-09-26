package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
	"waf/internal/config"
	"waf/internal/proxy"
	"waf/internal/secure"
	"waf/internal/store"
	"waf/internal/tlsmgr"
)

type fixture struct {
	handler *Handler
	store   *store.Store
	engine  *proxy.Engine
	secret  string
	boot    config.Bootstrap
}

func setup(t *testing.T, development bool) *fixture {
	t.Helper()
	b := config.DefaultBootstrap()
	b.DataDir = t.TempDir()
	b.MasterKeyFile = filepath.Join(b.DataDir, "master.key")
	b.AdminDomain = "admin.example.com"
	b.Development = development
	if err := secure.CreateKey(b.MasterKeyFile); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, _, err := s.CreateUser("admin", "admin test password", "admin", "test")
	if err != nil {
		t.Fatal(err)
	}
	e := proxy.New(b, s.Key(), s, nil)
	snapshot, err := e.Compile(config.Bundle{})
	if err != nil {
		t.Fatal(err)
	}
	e.Activate(snapshot, 0)
	certs := tlsmgr.New(b, s)
	h := New(b, s, e, certs)
	t.Cleanup(func() { certs.Close(); e.Close(); s.Close() })
	return &fixture{h, s, e, secret, b}
}
func (f *fixture) request(method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	scheme := "https"
	if f.boot.Development {
		scheme = "http"
	}
	r := httptest.NewRequest(method, scheme+"://admin.example.com/api/v1"+path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", scheme+"://admin.example.com")
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}
func (f *fixture) login(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	code := secure.TOTP(f.secret, time.Now().Unix()/30)
	w := f.request("POST", "/auth/login", map[string]string{"username": "admin", "password": "admin test password", "code": code}, nil, "")
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	var data struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &data)
	return w.Result().Cookies()[0], data.CSRF
}
func TestAuthenticationCSRFAndRBAC(t *testing.T) {
	f := setup(t, false)
	if w := f.request("GET", "/config/active", nil, nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated API")
	}
	cookie, csrf := f.login(t)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	if w := f.request("PUT", "/config/draft", map[string]any{}, cookie, ""); w.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	u, _, _, err := f.store.CreateUser("viewer", "viewer test password", "viewer", "test")
	if err != nil {
		t.Fatal(err)
	}
	token, viewerCSRF, err := f.store.NewSession(u)
	if err != nil {
		t.Fatal(err)
	}
	viewerCookie := &http.Cookie{Name: "__Host-waf_session", Value: token}
	if w := f.request("GET", "/credentials", nil, viewerCookie, viewerCSRF); w.Code != 403 {
		t.Fatal("viewer could access credentials")
	}
	if w := f.request("GET", "/events", nil, viewerCookie, viewerCSRF); w.Code != 200 {
		t.Fatal("viewer cannot view events")
	}
	if w := f.request("POST", "/auth/logout", map[string]any{}, cookie, csrf); w.Code != 200 {
		t.Fatal("logout")
	}
	if w := f.request("GET", "/auth/session", nil, cookie, ""); w.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}
func TestInvalidPublishKeepsActiveRevision(t *testing.T) {
	f := setup(t, true)
	cookie, csrf := f.login(t)
	d, _ := f.store.Draft()
	site := config.DefaultSite()
	site.ID = "site"
	site.Domains = []string{"site.example.com"}
	site.HTTPS = false
	site.RedirectHTTP = false
	site.Upstreams = []config.Upstream{{URL: "http://127.0.0.1:3000", Weight: 1}}
	site.Rules = []config.CustomRule{{ID: "broken", Enabled: true, Expression: "not valid CEL", Action: "block"}}
	d.Bundle = config.Bundle{Sites: []config.Site{site}}
	w := f.request("PUT", "/config/draft", d, cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("save: %s", w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &d)
	w = f.request("POST", "/config/publish", map[string]any{"version": d.Version, "base_revision": d.BaseRevision}, cookie, csrf)
	if w.Code != 400 || f.engine.Revision() != 0 {
		t.Fatalf("invalid publish %d rev %d", w.Code, f.engine.Revision())
	}
	d.Bundle.Sites[0].Rules[0].Expression = `request.path == "/blocked"`
	w = f.request("PUT", "/config/draft", d, cookie, csrf)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &d)
	w = f.request("POST", "/config/publish", map[string]any{"version": d.Version, "base_revision": d.BaseRevision}, cookie, csrf)
	if w.Code != 200 || f.engine.Revision() != 1 {
		t.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}
	w = f.request("POST", "/config/publish", map[string]any{"version": d.Version, "base_revision": d.BaseRevision}, cookie, csrf)
	if w.Code != 409 {
		t.Fatal("stale publish accepted")
	}
}
