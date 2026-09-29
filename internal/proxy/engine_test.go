package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"waf/internal/config"
	"waf/internal/store"
)

type sink struct{}

func (sink) Record(store.Event) {}
func testEngine(t *testing.T, upstream string, edit func(*config.Site)) (*Engine, *httptest.Server) {
	t.Helper()
	boot := config.DefaultBootstrap()
	boot.DataDir = t.TempDir()
	boot.AdminDomain = "console.example.com"
	boot.HTTPListen = "127.0.0.1:8080"
	boot.HTTPSListen = ""
	boot.Development = true
	s := config.DefaultSite()
	s.ID = "test"
	s.Name = "Test"
	s.Domains = []string{"site.example.com"}
	s.HTTPS = false
	s.RedirectHTTP = false
	s.Upstreams = []config.Upstream{{URL: upstream, Weight: 1}}
	s.Managed.Mode = "block"
	if edit != nil {
		edit(&s)
	}
	e := New(boot, bytes.Repeat([]byte{1}, 32), sink{}, nil)
	snapshot, err := e.Compile(config.Bundle{Sites: []config.Site{s}})
	if err != nil {
		t.Fatal(err)
	}
	e.Activate(snapshot, 1)
	srv := httptest.NewUnstartedServer(e)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() { srv.Close(); e.Close() })
	return e, srv
}
func request(t *testing.T, srv *httptest.Server, method, target string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "site.example.com"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func TestManagedAndCustomRules(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "origin")
	}))
	defer origin.Close()
	_, srv := testEngine(t, origin.URL, func(s *config.Site) {
		s.Rules = []config.CustomRule{{ID: "private", Enabled: true, Expression: `request.path.startsWith("/private")`, Action: "block"}}
	})
	for _, tc := range []struct {
		path string
		want int
	}{{"/hello", 200}, {"/private", 403}, {"/?id=" + url.QueryEscape("1' OR '1'='1' --"), 403}, {"/?q=" + url.QueryEscape("<script>alert(1)</script>"), 403}} {
		resp := request(t, srv, "GET", tc.path, nil)
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s status=%d body=%s", tc.path, resp.StatusCode, data)
		}
	}
}
func TestSSEAndHTTP2(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			io.WriteString(w, "data: second\n\n")
		}
	}))
	defer origin.Close()
	_, srv := testEngine(t, origin.URL, nil)
	start := time.Now()
	resp := request(t, srv, "GET", "/events", nil)
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("%q %v", line, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("SSE was buffered")
	}
}
func TestStreamingUpload(t *testing.T) {
	received := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 5)
		if _, e := io.ReadFull(r.Body, buf); e == nil {
			close(received)
		}
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok")
	}))
	defer origin.Close()
	_, srv := testEngine(t, origin.URL, func(s *config.Site) {
		s.Routes = []config.RoutePolicy{{PathPrefix: "/upload", BodyMode: "stream", MaxBodyBytes: 1024, IdleTimeoutSeconds: 5, MaxDurationSeconds: 10, MaxConcurrent: 4}}
	})
	reader, writer := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/upload", reader)
	req.Host = "site.example.com"
	req.Header.Set("Content-Type", "application/octet-stream")
	finished := make(chan error, 1)
	go func() {
		resp, e := srv.Client().Do(req)
		if e == nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				data, _ := io.ReadAll(resp.Body)
				e = &testError{string(data)}
			}
		}
		finished <- e
	}()
	writer.Write([]byte("hello"))
	select {
	case <-received:
	case err := <-finished:
		t.Fatalf("stream request ended before forwarding: %v", err)
	case <-ctx.Done():
		t.Fatal("upstream did not receive the body before EOF")
	}
	writer.Write([]byte(" world"))
	writer.Close()
	if e := <-finished; e != nil {
		t.Fatal(e)
	}
}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }
func TestWebSocketAndReload(t *testing.T) {
	origin := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) { io.Copy(ws, ws) }))
	defer origin.Close()
	engine, srv := testEngine(t, origin.URL, nil)
	u, _ := url.Parse(srv.URL)
	cfg, err := websocket.NewConfig("wss://"+u.Host+"/socket", "https://site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Location.Host = u.Host
	cfg.Header.Set("Host", "site.example.com")
	cfg.TlsConfig = &tls.Config{InsecureSkipVerify: true} // isolated httptest certificate
	// The WebSocket client derives Host from Location, so adapt it only in this test server.
	base := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = "site.example.com"; base.ServeHTTP(w, r) })
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err = websocket.Message.Send(ws, "before"); err != nil {
		t.Fatal(err)
	}
	var reply string
	if err = websocket.Message.Receive(ws, &reply); err != nil || reply != "before" {
		t.Fatalf("%q %v", reply, err)
	}
	old, release := engine.Snapshot()
	bundle := old.Bundle
	release()
	next, err := engine.Compile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	engine.Activate(next, 2)
	if err = websocket.Message.Send(ws, "after"); err != nil {
		t.Fatal(err)
	}
	if err = websocket.Message.Receive(ws, &reply); err != nil || reply != "after" {
		t.Fatalf("%q %v", reply, err)
	}
}
func TestBodyLimitAndEncoding(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
	defer origin.Close()
	_, srv := testEngine(t, origin.URL, func(s *config.Site) {
		s.Routes = []config.RoutePolicy{{PathPrefix: "/", BodyMode: "inspect", MaxBodyBytes: 16, IdleTimeoutSeconds: 5, MaxConcurrent: 4}}
	})
	resp := request(t, srv, "POST", "/", strings.NewReader(`{"value":"too much content"}`))
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestMultipartReplayAndCleanup(t *testing.T) {
	var payload bytes.Buffer
	writer := multipart.NewWriter(&payload)
	writer.WriteField("description", "uploaded document")
	file, err := writer.CreateFormFile("document", "notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(file, strings.Repeat("plain document text\n", 18000))
	writer.Close()
	want := bytes.Clone(payload.Bytes())
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, want) {
			t.Error("multipart body changed during inspection")
		}
		w.WriteHeader(204)
	}))
	defer origin.Close()
	e, srv := testEngine(t, origin.URL, nil)
	r, _ := http.NewRequest("POST", srv.URL+"/documents", &payload)
	r.Host = "site.example.com"
	r.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	entries, err := os.ReadDir(filepath.Join(e.Boot.DataDir, "tmp"))
	if err != nil || len(entries) != 0 || e.budget.Used() != 0 {
		t.Fatalf("inspection resources retained: %v %v budget=%d", entries, err, e.budget.Used())
	}
}

func TestUnknownLengthStreamLimit(t *testing.T) {
	forwarded := make(chan int64, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		forwarded <- n
	}))
	defer origin.Close()
	_, srv := testEngine(t, origin.URL, func(s *config.Site) {
		s.Routes = []config.RoutePolicy{{PathPrefix: "/upload", BodyMode: "stream", MaxBodyBytes: 1024, IdleTimeoutSeconds: 5, MaxDurationSeconds: 10, MaxConcurrent: 4}}
	})
	// Hide the known length to exercise chunked / HTTP/2 streaming enforcement.
	r, _ := http.NewRequest("POST", srv.URL+"/upload", io.NopCloser(strings.NewReader(strings.Repeat("a", 2048))))
	r.Host = "site.example.com"
	r.Header.Set("Content-Type", "application/octet-stream")
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case n := <-forwarded:
		if n > 1024 {
			t.Fatalf("forwarded %d bytes past limit", n)
		}
	case <-time.After(time.Second):
		// Transport may abort before sending even the request headers.
	}
}

func TestUpstreamHTTP2AndForwardingHeaders(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol %s", r.Proto)
		}
		json.NewEncoder(w).Encode(r.Header)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	e, srv := testEngine(t, origin.URL, nil)
	s, release := e.Snapshot()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	s.sites[0].transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	release()
	r, _ := http.NewRequest("GET", srv.URL+"/", nil)
	r.Host = "site.example.com"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	r.Header.Set("X-Real-IP", "1.1.1.1")
	r.Header.Set("CF-Connecting-IP", "1.1.1.1")
	r.Header.Set("True-Client-IP", "1.1.1.1")
	r.Header.Set("Forwarded", "for=1.1.1.1")
	r.Header.Set("Cookie", "app_session=kept; waf_clearance_dev=secret")
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var headers http.Header
	if err := json.NewDecoder(resp.Body).Decode(&headers); err != nil {
		t.Fatal(err)
	}
	if headers.Get("X-Forwarded-For") != "127.0.0.1" || headers.Get("X-Real-IP") != "127.0.0.1" || headers.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("untrusted forwarding identity: %v", headers)
	}
	if headers.Get("Forwarded") != "" || headers.Get("CF-Connecting-IP") != "" || headers.Get("True-Client-IP") != "" || headers.Get("Cookie") != "app_session=kept" {
		t.Fatalf("private or untrusted headers forwarded: %v", headers)
	}
}

func TestDrainAndProxyLoop(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	e, srv := testEngine(t, origin.URL, nil)
	r, _ := http.NewRequest("GET", srv.URL+"/", nil)
	r.Host = "site.example.com"
	r.Header.Set("X-WAF-Node", e.loopID)
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 508 {
		t.Fatalf("loop status %d", resp.StatusCode)
	}
	e.BeginDrain()
	if e.Ready() {
		t.Fatal("draining node still ready")
	}
	resp = request(t, srv, "GET", "/", nil)
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("drain status %d", resp.StatusCode)
	}
}

func TestManagedExceptionScopeAndObserve(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	_, srv := testEngine(t, origin.URL, func(s *config.Site) {
		s.Managed.Exclusions = []config.Exclusion{{RuleID: 913100, PathPrefix: "/trusted", Target: "REQUEST_HEADERS:User-Agent"}}
	})
	for _, tc := range []struct {
		path   string
		status int
	}{{"/normal", 403}, {"/trusted/document", 204}} {
		r, _ := http.NewRequest("GET", srv.URL+tc.path, nil)
		r.Host = "site.example.com"
		r.Header.Set("User-Agent", "sqlmap/1.8")
		resp, err := srv.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s status %d", tc.path, resp.StatusCode)
		}
	}
	_, observing := testEngine(t, origin.URL, func(s *config.Site) { s.Managed.Mode = "observe" })
	resp := request(t, observing, "GET", "/?q="+url.QueryEscape("<script>alert(1)</script>"), nil)
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("observe blocked request: %d", resp.StatusCode)
	}
}

func TestSecurityActionExecution(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	for _, action := range []string{"block", "log", "managed_challenge", "non_interactive_challenge", "interactive_challenge"} {
		t.Run(action, func(t *testing.T) {
			_, srv := testEngine(t, origin.URL, func(s *config.Site) {
				s.Managed.Mode = "off"
				s.Rules = []config.CustomRule{{ID: "rule", Enabled: true, Expression: "true", Action: action}}
			})
			resp := request(t, srv, "GET", "/protected", nil)
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			if action == "log" {
				if resp.StatusCode != 200 {
					t.Fatalf("log interrupted request: %s", raw)
				}
				return
			}
			if resp.StatusCode != 403 {
				t.Fatalf("expected denial: %d %s", resp.StatusCode, raw)
			}
			if config.IsChallengeAction(action) {
				var response map[string]string
				json.Unmarshal(raw, &response)
				mode := "non_interactive"
				if action == "interactive_challenge" {
					mode = "interactive"
				}
				if response["action"] != action || response["challenge_mode"] != mode || response["challenge_url"] == "" {
					t.Fatalf("wrong challenge: %s", raw)
				}
			}
		})
	}
}
func TestSkipPhasesAndResourceLimits(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	_, srv := testEngine(t, origin.URL, func(s *config.Site) {
		s.Rules = []config.CustomRule{
			{ID: "skip-custom", Enabled: true, Priority: 1, Expression: `request.path == "/custom"`, Action: "skip", Skip: []string{"custom_rules"}},
			{ID: "skip-one", Enabled: true, Priority: 1, Expression: `request.path == "/one"`, Action: "skip", Skip: []string{"rule:blocked"}},
			{ID: "skip-rates", Enabled: true, Priority: 1, Expression: `request.path == "/rates"`, Action: "skip", Skip: []string{"rate_limits"}},
			{ID: "skip-rate", Enabled: true, Priority: 1, Expression: `request.path == "/rate"`, Action: "skip", Skip: []string{"rate:limit"}},
			{ID: "skip-managed", Enabled: true, Priority: 1, Expression: `request.path == "/managed"`, Action: "skip", Skip: []string{"managed"}},
			{ID: "skip-bypass", Enabled: true, Priority: 1, Expression: `request.path == "/bypass"`, Action: "skip", Skip: []string{"custom_rules", "rate_limits", "managed"}},
			{ID: "blocked", Enabled: true, Priority: 2, Expression: `request.path in ["/custom", "/one", "/blocked"]`, Action: "block"},
		}
		s.RateLimits = []config.RateLimitPolicy{{ID: "limit", Enabled: true, Expression: `request.path in ["/rates", "/rate", "/limited"]`, Key: "ip_path", RequestsPerSecond: 0.001, Burst: 1}}
		s.Routes[0].MaxBodyBytes = 1024
	})
	for _, path := range []string{"/custom", "/one", "/rates", "/rate"} {
		for i := 0; i < 2; i++ {
			r := request(t, srv, "GET", path, nil)
			r.Body.Close()
			if r.StatusCode != 200 {
				t.Fatalf("skip %s: %d", path, r.StatusCode)
			}
		}
	}
	for _, tc := range []struct {
		path string
		want int
	}{{"/blocked", 403}, {"/limited", 200}, {"/limited", 429}, {"/managed?q=" + url.QueryEscape("<script>alert(1)</script>"), 200}, {"/?q=" + url.QueryEscape("<script>alert(1)</script>"), 403}} {
		r := request(t, srv, "GET", tc.path, nil)
		r.Body.Close()
		if r.StatusCode != tc.want {
			t.Fatalf("%s: %d != %d", tc.path, r.StatusCode, tc.want)
		}
	}
	r := request(t, srv, "POST", "/bypass", strings.NewReader(strings.Repeat("x", 1025)))
	r.Body.Close()
	if r.StatusCode != 413 {
		t.Fatal("Skip bypassed resource limit")
	}
}
