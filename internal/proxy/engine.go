package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/prometheus/client_golang/prometheus"
	"waf/internal/config"
	"waf/internal/guard"
	"waf/internal/policy"
	"waf/internal/secure"
	"waf/internal/store"
)

type EventSink interface{ Record(store.Event) }
type Engine struct {
	Boot      config.Bootstrap
	PublishMu sync.Mutex
	mu        sync.RWMutex
	current   *Snapshot
	limits    *guard.Limits
	budget    *guard.Budget
	challenge *guard.Challenge
	trusted   []netip.Prefix
	sink      EventSink
	requests  *prometheus.CounterVec
	latency   *prometheus.HistogramVec
	inflight  prometheus.Gauge
	active    atomic.Int64
	workersMu sync.Mutex
	workers   sync.WaitGroup
	draining  bool
	loopID    string
}
type Snapshot struct {
	Revision int64
	Bundle   config.Bundle
	compiled *policy.Compiled
	sites    []*siteRuntime
	refs     atomic.Int64
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
}
type siteRuntime struct {
	policy      *policy.Site
	upstreams   []*upstream
	round       atomic.Uint64
	transport   *http.Transport
	wsTransport *http.Transport
}
type upstream struct {
	URL            *url.URL
	weight         int
	healthPath     string
	unhealthyUntil atomic.Int64
}

func New(boot config.Bootstrap, key []byte, sink EventSink, reg prometheus.Registerer) *Engine {
	e := &Engine{Boot: boot, limits: guard.NewLimits(boot.MaxRateEntries), budget: guard.NewBudget(boot.BodyBudgetBytes), challenge: guard.NewChallenge(key, boot.Development), trusted: guard.ParseCIDRs(boot.TrustedProxies), sink: sink, loopID: secure.Random(24)}
	e.requests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "waf_requests_total", Help: "Completed requests by bounded site and action labels."}, []string{"site", "action", "status"})
	e.latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "waf_request_duration_seconds", Help: "Full request duration, including streams.", Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, 1, 5, 30, 300, 3600}}, []string{"site"})
	e.inflight = prometheus.NewGauge(prometheus.GaugeOpts{Name: "waf_inflight_requests", Help: "Active requests and streams."})
	if reg != nil {
		reg.MustRegister(e.requests, e.latency, e.inflight, prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "waf_body_reserved_bytes", Help: "Reserved body memory and temporary storage budget."}, func() float64 { return float64(e.budget.Used()) }))
	}
	return e
}
func (e *Engine) Compile(bundle config.Bundle) (*Snapshot, error) {
	raw, _ := json.Marshal(bundle)
	var copy config.Bundle
	if err := json.Unmarshal(raw, &copy); err != nil {
		return nil, err
	}
	if err := copy.NormalizeAndValidate(e.Boot); err != nil {
		return nil, err
	}
	tmp := filepath.Join(e.Boot.DataDir, "tmp")
	if err := os.MkdirAll(tmp, 0700); err != nil {
		return nil, err
	}
	compiled, err := policy.Compile(copy, e.Boot)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Snapshot{Bundle: copy, compiled: compiled, ctx: ctx, cancel: cancel}
	s.refs.Store(1)
	for _, p := range compiled.Sites {
		rt := &siteRuntime{policy: p, transport: newTransport(e.Boot, false), wsTransport: newTransport(e.Boot, true)}
		for _, u := range p.Config.Upstreams {
			parsed, _ := url.Parse(u.URL)
			rt.upstreams = append(rt.upstreams, &upstream{URL: parsed, weight: u.Weight, healthPath: u.HealthPath})
		}
		s.sites = append(s.sites, rt)
	}
	return s, nil
}
func (s *Snapshot) Release() {
	if s.refs.Add(-1) == 0 {
		s.once.Do(func() {
			s.cancel()
			s.wg.Wait()
			for _, site := range s.sites {
				site.transport.CloseIdleConnections()
				site.wsTransport.CloseIdleConnections()
			}
			s.compiled.Close()
		})
	}
}
func (e *Engine) Activate(s *Snapshot, revision int64) {
	s.Revision = revision
	for _, site := range s.sites {
		if !site.policy.Config.Enabled {
			continue
		}
		for _, up := range site.upstreams {
			if up.healthPath == "" {
				continue
			}
			s.wg.Add(1)
			go s.healthLoop(site, up)
		}
	}
	e.mu.Lock()
	old := e.current
	e.current = s
	e.active.Store(revision)
	e.mu.Unlock()
	if old != nil {
		old.cancel()
		old.Release()
	}
}
func (e *Engine) Snapshot() (*Snapshot, func()) {
	e.mu.RLock()
	s := e.current
	if s != nil {
		s.refs.Add(1)
	}
	e.mu.RUnlock()
	var once sync.Once
	return s, func() {
		once.Do(func() {
			if s != nil {
				s.Release()
			}
		})
	}
}
func (e *Engine) Close() {
	e.mu.Lock()
	old := e.current
	e.current = nil
	e.mu.Unlock()
	if old != nil {
		old.cancel()
		old.Release()
	}
}
func (e *Engine) BeginDrain() { e.workersMu.Lock(); e.draining = true; e.workersMu.Unlock() }
func (e *Engine) Ready() bool { e.workersMu.Lock(); defer e.workersMu.Unlock(); return !e.draining }
func (e *Engine) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { e.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
func (e *Engine) Revision() int64 { return e.active.Load() }
func (s *Snapshot) find(host string) *siteRuntime {
	for _, site := range s.sites {
		if !site.policy.Config.Enabled {
			continue
		}
		for _, d := range site.policy.Config.Domains {
			if d == host {
				return site
			}
		}
	}
	for _, site := range s.sites {
		if !site.policy.Config.Enabled {
			continue
		}
		for _, d := range site.policy.Config.Domains {
			if config.MatchesDomain(d, host) {
				return site
			}
		}
	}
	return nil
}
func (rt *siteRuntime) choose() *upstream {
	now := time.Now().Unix()
	total := 0
	for _, u := range rt.upstreams {
		if u.unhealthyUntil.Load() <= now {
			total += u.weight
		}
	}
	if total == 0 {
		return nil
	}
	pick := int(rt.round.Add(1) % uint64(total))
	for _, u := range rt.upstreams {
		if u.unhealthyUntil.Load() > now {
			continue
		}
		if pick < u.weight {
			return u
		}
		pick -= u.weight
	}
	return nil
}
func (s *Snapshot) healthLoop(site *siteRuntime, up *upstream) {
	defer s.wg.Done()
	client := &http.Client{Transport: site.transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	check := func() {
		target := *up.URL
		target.Path = up.healthPath
		r, err := http.NewRequestWithContext(s.ctx, "GET", target.String(), nil)
		if err != nil {
			return
		}
		resp, err := client.Do(r)
		if err != nil {
			if s.ctx.Err() == nil {
				up.unhealthyUntil.Store(time.Now().Add(15 * time.Second).Unix())
			}
			return
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			up.unhealthyUntil.Store(time.Now().Add(15 * time.Second).Unix())
		} else {
			up.unhealthyUntil.Store(0)
		}
	}
	check()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
func (e *Engine) UpstreamStatus() []map[string]any {
	s, release := e.Snapshot()
	defer release()
	out := []map[string]any{}
	if s == nil {
		return out
	}
	for _, site := range s.sites {
		for _, u := range site.upstreams {
			out = append(out, map[string]any{"site_id": site.policy.Config.ID, "url": u.URL.String(), "healthy": u.unhealthyUntil.Load() <= time.Now().Unix(), "health_path": u.healthPath})
		}
	}
	return out
}
func newTransport(boot config.Bootstrap, websocket bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.MaxIdleConns = 512
	t.MaxIdleConnsPerHost = 64
	t.MaxConnsPerHost = 2048
	t.IdleConnTimeout = 90 * time.Second
	t.ResponseHeaderTimeout = 30 * time.Second
	t.TLSHandshakeTimeout = 10 * time.Second
	t.MaxResponseHeaderBytes = 64 << 10
	t.DisableCompression = true
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP1(true)
	t.Protocols.SetHTTP2(!websocket)
	t.ForceAttemptHTTP2 = !websocket
	ports := map[string]bool{}
	for _, listen := range []string{boot.HTTPListen, boot.HTTPSListen, boot.OpsListen} {
		_, port, err := net.SplitHostPort(listen)
		if err == nil {
			ports[port] = true
		}
	}
	local := map[netip.Addr]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err == nil {
				local[p.Addr().Unmap()] = true
			}
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		var last error
		for _, ip := range ips {
			ip = ip.Unmap()
			if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ports[port] && (ip.IsLoopback() || local[ip]) {
				last = errors.New("upstream points to a reserved or WAF listener address")
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			last = errors.New("no upstream address")
		}
		return nil, last
	}
	return t
}

func (e *Engine) ServeHTTP(raw http.ResponseWriter, r *http.Request) {
	e.workersMu.Lock()
	if e.draining {
		e.workersMu.Unlock()
		http.Error(raw, "node is draining", 503)
		return
	}
	e.workers.Add(1)
	e.workersMu.Unlock()
	defer e.workers.Done()
	start := time.Now()
	w := &responseWriter{ResponseWriter: raw, idle: 300 * time.Second}
	event := store.Event{RequestID: secure.Random(16), ClientIP: guard.ClientIP(r, e.trusted).String(), Method: r.Method, Path: r.URL.Path, Action: "allow", Inspection: "headers"}
	var bounded *idleBody
	w.Header().Set("X-Request-ID", event.RequestID)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		panicValue := recover()
		if panicValue != nil {
			event.Action = "error"
			event.Message = "request or stream interrupted"
			if w.status == 0 {
				w.status = 500
			}
		}
		if bounded != nil && bounded.exceeded.Load() {
			event.Action = "block"
			event.Message = "stream body limit exceeded"
		}
		event.Status = w.status
		if event.Status == 0 {
			event.Status = 200
		}
		event.Bytes = w.bytes
		event.DurationMS = time.Since(start).Milliseconds()
		if e.sink != nil && event.Action != "challenge_asset" {
			e.sink.Record(event)
		}
		e.requests.WithLabelValues(event.SiteID, event.Action, strconv.Itoa(event.Status)).Inc()
		e.latency.WithLabelValues(event.SiteID).Observe(time.Since(start).Seconds())
		if panicValue != nil {
			panic(panicValue)
		}
	}()
	deny := func(status int, action, message string) {
		event.Action = action
		event.Message = message
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": message, "request_id": event.RequestID})
	}
	if r.Header.Get("X-WAF-Node") == e.loopID {
		deny(508, "block", "proxy_loop")
		return
	}
	done, ok := e.limits.Acquire("global", e.Boot.MaxInFlight)
	if !ok {
		deny(503, "resource_limit", "inflight_limit")
		return
	}
	defer done()
	e.inflight.Inc()
	defer e.inflight.Dec()
	snapshot, releaseSnapshot := e.Snapshot()
	defer releaseSnapshot()
	if snapshot == nil {
		deny(503, "error", "not_ready")
		return
	}
	event.Revision = snapshot.Revision
	host := config.Host(r.Host)
	site := snapshot.find(host)
	if site == nil {
		deny(421, "block", "unknown_host")
		return
	}
	cfg := site.policy.Config
	event.SiteID = cfg.ID
	uriLimit := 8192
	if r.URL.Path == guard.ChallengePath || r.URL.Path == guard.ChallengePath+"/puzzle" {
		uriLimit = 24 << 10
	}
	if len(r.URL.RequestURI()) > uriLimit || r.URL.IsAbs() || strings.ContainsAny(r.URL.Path, "\\\x00\r\n") || strings.Contains(r.URL.RawQuery, ";") {
		deny(400, "block", "invalid_request_target")
		return
	}
	if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		deny(400, "block", "invalid_query_encoding")
		return
	}
	for _, escaped := range []string{"%2f", "%5c", "%2e", "%00"} {
		if strings.Contains(strings.ToLower(r.URL.Path), escaped) {
			deny(400, "block", "ambiguous_path_encoding")
			return
		}
	}
	if len(r.TransferEncoding) > 1 || len(r.TransferEncoding) > 0 && r.ContentLength >= 0 || r.Method == "CONNECT" || strings.ContainsAny(r.Host, "\r\n /\\") {
		deny(400, "block", "invalid_request_framing")
		return
	}
	if cfg.RedirectHTTP && r.TLS == nil {
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), 308)
		event.Action = "redirect"
		return
	}
	if strings.HasPrefix(r.URL.Path, "/.waf/") {
		result := e.challenge.Serve(w, r, cfg.ID, event.ClientIP, event.Revision)
		event.Action, event.RuleID, event.ChallengeMode = result.Action, result.RuleID, result.Mode
		return
	}
	route := cfg.Route(config.CanonicalPath(r.URL.Path), r.Method)
	w.idle = time.Duration(route.IdleTimeoutSeconds) * time.Second
	isWS := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if route.BodyMode == "stream" && (r.URL.EscapedPath() != r.URL.Path || path.Clean(r.URL.Path) != strings.TrimSuffix(r.URL.Path, "/") && r.URL.Path != "/") {
		deny(400, "block", "ambiguous_stream_path")
		return
	}
	if r.ContentLength > route.MaxBodyBytes {
		deny(413, "block", "body_limit")
		return
	}
	doneRoute, ok := e.limits.Acquire("route:"+cfg.ID+":"+route.PathPrefix, route.MaxConcurrent)
	if !ok {
		deny(503, "resource_limit", "route_concurrency_limit")
		return
	}
	defer doneRoute()
	if isWS {
		if !validWebSocket(r, cfg) {
			deny(403, "block", "websocket_origin_or_handshake_rejected")
			return
		}
		d, ok := e.limits.Acquire("ws:"+cfg.ID+":"+event.ClientIP, cfg.MaxConnectionsPerIP)
		if !ok {
			deny(429, "rate_limit", "websocket_connection_limit")
			return
		}
		defer d()
		if !e.limits.Allow("ws-new:"+cfg.ID+":"+event.ClientIP, 1, 10, 0) {
			deny(429, "rate_limit", "websocket_handshake_rate")
			return
		}
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if route.MaxDurationSeconds > 0 {
		ctx, cancel = context.WithTimeout(r.Context(), time.Duration(route.MaxDurationSeconds)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(r.Context())
	}
	defer cancel()
	r = r.Clone(ctx)
	r.Header.Del("X-WAF-Inspection")
	data := policy.RequestData(r, event.ClientIP)
	skip := map[string]bool{}
	for _, rule := range site.policy.Rules {
		rc := rule.Config
		if !rc.Enabled || skip["custom_rules"] || skip["rule:"+rc.ID] {
			continue
		}
		matches, err := rule.Expression.Eval(ctx, data)
		if err != nil {
			event.RuleID = rc.ID
			deny(503, "error", "custom_rule_execution_failed")
			return
		}
		if !matches {
			continue
		}
		event.RuleID = rc.ID
		switch rc.Action {
		case "block":
			deny(403, "block", "custom_rule")
			return
		case "log":
			event.Action = "log"
		case "managed_challenge", "non_interactive_challenge", "interactive_challenge":
			mode := e.challenge.Mode(cfg.ID, rc.ID, event.ClientIP, rc.Action, event.Revision)
			if !e.challenge.Cleared(r, cfg.ID, rc.ID, event.ClientIP, event.Revision) {
				event.Action, event.ChallengeMode = rc.Action, mode
				e.challenge.Deny(w, r, cfg.ID, rc.ID, event.ClientIP, event.Revision, rc.Action, mode, *rc.Challenge)
				return
			}
		case "skip":
			event.Action = "skip"
			for _, target := range rc.Skip {
				skip[target] = true
			}
		}
	}
	for _, rate := range site.policy.Rates {
		rc := rate.Config
		if !rc.Enabled || skip["rate_limits"] || skip["rate:"+rc.ID] {
			continue
		}
		matches, err := rate.Expression.Eval(ctx, data)
		if err != nil {
			deny(503, "error", "rate_rule_execution_failed")
			return
		}
		if !matches {
			continue
		}
		key := cfg.ID + ":" + rc.ID
		if rc.Key != "site" {
			key += ":" + event.ClientIP
		}
		if rc.Key == "ip_path" {
			key += ":" + r.URL.Path
		}
		if !e.limits.Allow("rate:"+key, rc.RequestsPerSecond, rc.Burst, time.Duration(rc.BanSeconds)*time.Second) {
			event.RuleID = rc.ID
			w.Header().Set("Retry-After", strconv.Itoa(max(1, rc.BanSeconds)))
			deny(429, "rate_limit", "rate_limit")
			return
		}
	}
	var tx types.Transaction
	var body *spool
	var releaseBudget func()
	var resources sync.Once
	finishInspection := func() {
		resources.Do(func() {
			if tx != nil {
				for _, match := range tx.MatchedRules() {
					id := match.Rule().ID()
					if id >= 200000 && id < 200010 {
						event.Inspection = "parse_failed"
						event.Message = "request body parser reported an error"
						if event.Action == "allow" {
							event.Action = "observe"
						}
					}
					if !policy.Tunable(id) {
						continue
					}
					if len(event.MatchedRuleIDs) == 0 {
						event.RuleID = strconv.Itoa(id)
						event.Message = policy.Description(id)
					}
					if len(event.MatchedRuleIDs) < 20 {
						event.MatchedRuleIDs = append(event.MatchedRuleIDs, id)
					}
					if event.Action == "allow" {
						event.Action = "observe"
					}
				}
				tx.ProcessLogging()
				tx.Close()
			}
			if body != nil {
				body.Close()
			}
			if releaseBudget != nil {
				releaseBudget()
			}
			releaseSnapshot()
		})
	}
	defer finishInspection()
	if cfg.Managed.Mode != "off" && !skip["managed"] {
		tx = site.policy.Managed[policy.Profile(route)].NewTransaction()
		tx.ProcessConnection(event.ClientIP, 0, "", 0)
		tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
		tx.SetServerName(host)
		for key, vals := range r.Header {
			for _, v := range vals {
				tx.AddRequestHeader(key, v)
			}
		}
		tx.AddRequestHeader("Host", r.Host)
		for _, te := range r.TransferEncoding {
			tx.AddRequestHeader("Transfer-Encoding", te)
		}
		if it := tx.ProcessRequestHeaders(); it != nil {
			deny(403, "block", "managed_rule")
			return
		}
	}
	original := r.Body
	if original != nil && original != http.NoBody {
		bounded = &idleBody{ReadCloser: original, rc: http.NewResponseController(raw), idle: w.idle, remaining: route.MaxBodyBytes}
		defer bounded.Close()
		r.Body = bounded
		if route.BodyMode == "inspect" {
			encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
			if encoding != "" && encoding != "identity" {
				deny(415, "block", "unsupported_content_encoding")
				return
			}
			reserve := route.MaxBodyBytes
			if r.ContentLength >= 0 {
				reserve = r.ContentLength
			}
			// The replay spool, Coraza body buffer and extracted multipart files
			// may coexist until inspection and upstream request transmission finish.
			releaseBudget, ok = e.budget.Reserve(reserve * 3)
			if !ok {
				deny(503, "resource_limit", "body_budget_exhausted")
				return
			}
			var err error
			var n int64
			body, n, err = bufferBody(bounded, route.MaxBodyBytes, filepath.Join(e.Boot.DataDir, "tmp"))
			if err != nil {
				var maxErr *http.MaxBytesError
				if errors.Is(err, errBodyLimit) || errors.As(err, &maxErr) {
					deny(413, "block", "body_limit")
				} else {
					deny(400, "block", "request_body_read_failed")
				}
				return
			}
			bounded.Close()
			r.ContentLength = n
			r.TransferEncoding = nil
			r.Body = body
			event.Inspection = "body_uninspected"
			if tx != nil {
				event.Inspection = "full"
				it, _, err := tx.ReadRequestBodyFrom(body)
				body.Rewind()
				if err != nil {
					deny(400, "block", "request_body_parse_failed")
					return
				}
				if it != nil {
					deny(403, "block", "managed_rule")
					return
				}
			}
		} else {
			event.Inspection = "stream_headers_only"
			if r.ProtoMajor == 1 {
				if err := http.NewResponseController(raw).EnableFullDuplex(); err != nil {
					deny(503, "error", "full_duplex_not_supported")
					return
				}
			}
		}
	}
	if tx != nil {
		it, err := tx.ProcessRequestBody()
		if err != nil {
			if cfg.Managed.Mode == "block" {
				deny(503, "error", "managed_inspection_failed")
				return
			}
			event.Action = "observe"
			event.Message = "managed inspection failed"
		}
		if it != nil {
			deny(403, "block", "managed_rule")
			return
		}
	}
	u := site.choose()
	if u == nil {
		deny(503, "error", "no_healthy_upstream")
		return
	}
	transport := http.RoundTripper(site.transport)
	if isWS {
		transport = site.wsTransport
	}
	proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: 0, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(u.URL)
		p.Out.Host = r.Host
		p.Out.Header.Set("X-Forwarded-For", event.ClientIP)
		p.Out.Header.Set("X-Real-IP", event.ClientIP)
		p.Out.Header.Del("CF-Connecting-IP")
		p.Out.Header.Del("True-Client-IP")
		// Clearance is a WAF credential, never an application cookie.
		var cookies []string
		for _, line := range p.Out.Header.Values("Cookie") {
			for _, part := range strings.Split(line, ";") {
				name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
				if name != "__Host-waf_clearance" && name != "waf_clearance_dev" {
					cookies = append(cookies, part)
				}
			}
		}
		p.Out.Header.Del("Cookie")
		if len(cookies) > 0 {
			p.Out.Header.Set("Cookie", strings.Join(cookies, ";"))
		}
		p.Out.Header.Set("X-Forwarded-Host", r.Host)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		p.Out.Header.Set("X-Forwarded-Proto", scheme)
		p.Out.Header.Set("X-Request-ID", event.RequestID)
		p.Out.Header.Set("X-WAF-Inspection", event.Inspection)
		p.Out.Header.Set("X-WAF-Node", e.loopID)
	}, ModifyResponse: func(resp *http.Response) error {
		if tx != nil {
			for key, vals := range resp.Header {
				for _, v := range vals {
					tx.AddResponseHeader(key, v)
				}
			}
			if it := tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto); it != nil {
				return errors.New("managed response header rejection")
			}
			if it, err := tx.ProcessResponseBody(); err != nil || it != nil {
				return errors.New("managed response inspection failed")
			}
		}
		if resp.StatusCode == 101 {
			w.status = 101
			if rwc, ok := resp.Body.(io.ReadWriteCloser); ok {
				resp.Body = &idleDuplex{ReadWriteCloser: rwc, idle: w.idle, cancel: cancel}
			}
		} else {
			resp.Body = &idleResponseBody{ReadCloser: resp.Body, idle: w.idle, cancel: cancel}
		}
		if ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); ct == "text/event-stream" {
			resp.Header.Set("X-Accel-Buffering", "no")
		}
		finishInspection()
		return nil
	}, ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
		if ctx.Err() != nil {
			event.Action = "cancelled"
			if w.status == 0 {
				w.status = 499
			}
			return
		}
		if errors.Is(err, errBodyLimit) || bounded != nil && bounded.exceeded.Load() {
			deny(413, "block", "body_limit")
			return
		}
		u.unhealthyUntil.Store(time.Now().Add(5 * time.Second).Unix())
		slog.Warn("upstream request failed", "site", cfg.ID, "request_id", event.RequestID, "error", err)
		deny(502, "error", "upstream_failure")
	}}
	proxy.ServeHTTP(w, r)
}
func validWebSocket(r *http.Request, cfg config.Site) bool {
	if r.Method != "GET" || r.ProtoMajor != 1 || r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if len(cfg.WebSocketOrigins) == 0 {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		return origin == scheme+"://"+r.Host
	}
	for _, allowed := range cfg.WebSocketOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (e *Engine) ValidateExpression(source string, sample map[string]any) (bool, error) {
	p, err := policy.CompileExpression(source)
	if err != nil {
		return false, err
	}
	if sample == nil {
		return true, nil
	}
	return p.Eval(context.Background(), sample)
}
func (e *Engine) String() string { return fmt.Sprintf("WAF revision %d", e.Revision()) }
