package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"waf/internal/config"
	"waf/internal/store"
)

type eventCollector struct {
	mu     sync.Mutex
	events []store.Event
}

func (s *eventCollector) Record(e store.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}
func (s *eventCollector) last() store.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[len(s.events)-1]
}
func globalEngine(t *testing.T) (*Engine, config.Bundle, *eventCollector) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(origin.Close)
	boot := config.DefaultBootstrap()
	boot.DataDir = t.TempDir()
	boot.Development = true
	boot.AdminDomain = "admin.example.com"
	events := &eventCollector{}
	e := New(boot, bytes.Repeat([]byte{1}, 32), events, nil)
	t.Cleanup(e.Close)
	b := config.DefaultBundle()
	for _, id := range []string{"one", "two"} {
		s := config.DefaultSite()
		s.ID = id
		s.Domains = []string{id + ".example.com"}
		s.HTTPS = false
		s.RedirectHTTP = false
		s.Upstreams = []config.Upstream{{URL: origin.URL}}
		b.Sites = append(b.Sites, s)
	}
	return e, b, events
}
func activateGlobal(t *testing.T, e *Engine, b config.Bundle) {
	t.Helper()
	s, err := e.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	e.Activate(s, e.Revision()+1)
}
func globalRequest(e *Engine, site, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.Host = site + ".example.com"
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("X-Site-ID", "two")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}
func TestGlobalRulesScopeAndNewSites(t *testing.T) {
	e, b, events := globalEngine(t)
	b.Security.Managed.Default.Mode = "off"
	b.Security.CustomRules = []config.CustomRule{
		{ID: "only-one", Enabled: true, Action: "block", Scope: config.Scope{Mode: "sites", SiteIDs: []string{"one"}}, Expression: `request.path == "/scoped" && site.id == "one"`},
		{ID: "host", Enabled: true, Action: "block", Expression: `request.host == "two.example.com" && request.path == "/host"`},
		{ID: "all", Enabled: true, Action: "block", Expression: `request.path == "/global"`},
	}
	activateGlobal(t, e, b)
	for _, tc := range []struct {
		site, path string
		status     int
	}{{"one", "/scoped", 403}, {"two", "/scoped", 200}, {"one", "/host", 200}, {"two", "/host", 403}, {"one", "/global", 403}, {"two", "/global", 403}} {
		if w := globalRequest(e, tc.site, tc.path); w.Code != tc.status {
			t.Fatalf("%+v: %d %s", tc, w.Code, w.Body.String())
		}
	}
	third := b.Sites[0]
	third.ID = "three"
	third.Domains = []string{"three.example.com"}
	b.Sites = append(b.Sites, third)
	activateGlobal(t, e, b)
	if w := globalRequest(e, "three", "/global"); w.Code != 403 || events.last().RuleID != "all" {
		t.Fatal("new site did not inherit global rule")
	}
	if w := globalRequest(e, "three", "/scoped"); w.Code != 200 {
		t.Fatal("site scope widened")
	}
	b.Security.CustomRules[0].Expression = "broken CEL"
	if _, err := e.Compile(b); err == nil {
		t.Fatal("invalid compile accepted")
	}
	if w := globalRequest(e, "three", "/global"); w.Code != 403 {
		t.Fatal("failed compile affected active snapshot")
	}
}
func TestGlobalRateCountersRemainSiteLocal(t *testing.T) {
	e, b, _ := globalEngine(t)
	b.Security.Managed.Default.Mode = "off"
	for _, key := range []string{"site", "ip", "ip_path"} {
		b.Security.RateLimits = append(b.Security.RateLimits, config.RateLimitPolicy{ID: key, Enabled: true, Expression: `request.path == "/` + key + `"`, Key: key, RequestsPerSecond: 0.001, Burst: 1})
	}
	activateGlobal(t, e, b)
	for _, key := range []string{"site", "ip", "ip_path"} {
		for _, site := range []string{"one", "two"} {
			for _, want := range []int{200, 429} {
				if w := globalRequest(e, site, "/"+key); w.Code != want {
					t.Fatalf("%s %s: %d != %d", site, key, w.Code, want)
				}
			}
		}
	}
}
func TestManagedOverrideSelectionAndExceptionScope(t *testing.T) {
	e, b, events := globalEngine(t)
	b.Security.Managed.Default.Mode = "block"
	observe := config.DefaultManaged()
	off := config.DefaultManaged()
	off.Mode = "off"
	scoped := config.Scope{Mode: "sites", SiteIDs: []string{"one"}}
	b.Security.Managed.Overrides = []config.ManagedOverride{
		{ID: "disabled", Enabled: false, Priority: 0, Expression: "true", Policy: off},
		{ID: "off", Enabled: true, Priority: 1, Scope: scoped, Expression: `request.path == "/off"`, Policy: off},
		{ID: "observe", Enabled: true, Priority: 2, Scope: scoped, Expression: `request.path == "/observe"`, Policy: observe},
		{ID: "same-priority-later", Enabled: true, Priority: 2, Scope: scoped, Expression: `request.path == "/observe"`, Policy: b.Security.Managed.Default},
	}
	activateGlobal(t, e, b)
	attack := "?q=" + url.QueryEscape("<script>alert(1)</script>")
	for _, tc := range []struct {
		site, path string
		status     int
		policy     string
	}{{"one", "/off", 200, ""}, {"one", "/observe", 200, "observe"}, {"two", "/observe", 403, "default"}, {"one", "/default", 403, "default"}} {
		w := globalRequest(e, tc.site, tc.path+attack)
		event := events.last()
		if w.Code != tc.status || event.ManagedPolicyID != tc.policy {
			t.Fatalf("%+v: status=%d event=%+v", tc, w.Code, event)
		}
	}
	// A targeted detector exception in the shared default must not leak to another site.
	b.Security.Managed.Default.Exclusions = []config.Exclusion{{Scope: scoped, RuleID: 913100, PathPrefix: "/trusted", Target: "REQUEST_HEADERS:User-Agent"}}
	activateGlobal(t, e, b)
	for _, tc := range []struct {
		site, path string
		status     int
	}{{"one", "/trusted", 200}, {"one", "/elsewhere", 403}, {"two", "/trusted", 403}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = tc.site + ".example.com"
		r.Header.Set("User-Agent", "sqlmap")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if tc.status == 403 && events.last().RuleID != "913100" {
			t.Fatalf("control rule reported as detector: %+v", events.last())
		}
		if w.Code != tc.status {
			t.Fatalf("exception scope %+v: %d %s", tc, w.Code, w.Body.String())
		}
	}
	b.Security.Managed.Overrides = []config.ManagedOverride{{ID: "broken-runtime", Enabled: true, Expression: `request.missing == "x"`, Policy: observe}}
	activateGlobal(t, e, b)
	if w := globalRequest(e, "two", "/"); w.Code != 503 {
		t.Fatal("managed expression failure fell back to weaker protection")
	}
}
func TestEvaluateCompleteScope(t *testing.T) {
	e := &Engine{}
	scope := config.Scope{Mode: "sites", SiteIDs: []string{"one"}}
	for _, site := range []string{"one", "two"} {
		sample := map[string]any{"site": map[string]any{"id": site}, "request": map[string]any{"host": "one.example.com"}}
		got, err := e.ValidateExpression(`request.host == "one.example.com"`, scope, sample)
		if err != nil || got != (site == "one") {
			t.Fatalf("%s: %v %v", site, got, err)
		}
	}
	if _, err := e.ValidateExpression("true", scope, map[string]any{}); err == nil {
		t.Fatal("missing sample site accepted")
	}
}
