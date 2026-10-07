package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

const MiB = int64(1024 * 1024)

type Bootstrap struct {
	DataDir            string   `json:"data_dir"`
	MasterKeyFile      string   `json:"master_key_file"`
	HTTPListen         string   `json:"http_listen"`
	HTTPSListen        string   `json:"https_listen"`
	OpsListen          string   `json:"ops_listen"`
	AdminDomain        string   `json:"admin_domain"`
	AdminCIDRs         []string `json:"admin_cidrs"`
	TrustedProxies     []string `json:"trusted_proxies"`
	ACMEEmail          string   `json:"acme_email"`
	ACMECA             string   `json:"acme_ca,omitempty"`
	Development        bool     `json:"development"`
	MaxConnections     int      `json:"max_connections"`
	MaxInFlight        int      `json:"max_in_flight"`
	BodyBudgetBytes    int64    `json:"body_budget_bytes"`
	MaxRateEntries     int      `json:"max_rate_entries"`
	EventRetentionDays int      `json:"event_retention_days"`
	EventMaxRows       int      `json:"event_max_rows"`
}

func DefaultBootstrap() Bootstrap {
	return Bootstrap{DataDir: "/var/lib/waf", MasterKeyFile: "/etc/waf/master.key", HTTPListen: ":80", HTTPSListen: ":443", OpsListen: "127.0.0.1:9090", MaxConnections: 8192, MaxInFlight: 1024, BodyBudgetBytes: 256 * MiB, MaxRateEntries: 100000, EventRetentionDays: 7, EventMaxRows: 200000}
}

func Load(path string) (Bootstrap, error) {
	b := DefaultBootstrap()
	f, err := os.Open(path)
	if err != nil {
		return b, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&b); err != nil {
		return b, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return b, errors.New("configuration must contain exactly one JSON object")
	}
	return b, b.Validate()
}

func (b Bootstrap) Validate() error {
	if b.DataDir == "" || b.MasterKeyFile == "" {
		return errors.New("data_dir and master_key_file are required")
	}
	if !ValidDomain(b.AdminDomain, false) {
		return errors.New("admin_domain must be a DNS name without a port")
	}
	for _, v := range append(append([]string{}, b.TrustedProxies...), b.AdminCIDRs...) {
		if _, e := netip.ParsePrefix(v); e != nil {
			return fmt.Errorf("invalid CIDR %q", v)
		}
	}
	for _, v := range []string{b.HTTPListen, b.HTTPSListen, b.OpsListen} {
		if v == "" {
			continue
		}
		if _, _, e := net.SplitHostPort(v); e != nil {
			return fmt.Errorf("invalid listen address %q", v)
		}
	}
	if b.OpsListen != "" {
		h, _, _ := net.SplitHostPort(b.OpsListen)
		ip, e := netip.ParseAddr(h)
		if e != nil || !ip.IsLoopback() {
			return errors.New("ops listener must use a loopback IP")
		}
	}
	if b.Development {
		for _, v := range []string{b.HTTPListen, b.HTTPSListen} {
			if v == "" {
				continue
			}
			h, _, _ := net.SplitHostPort(v)
			ip, e := netip.ParseAddr(h)
			if e != nil || !ip.IsLoopback() {
				return errors.New("development listeners must use loopback IPs")
			}
		}
	} else if b.HTTPSListen == "" || b.ACMEEmail == "" {
		return errors.New("production requires HTTPS and acme_email")
	}
	if b.MaxConnections < 1 || b.MaxInFlight < 1 || b.BodyBudgetBytes < 24*MiB || b.MaxRateEntries < 100 || b.EventRetentionDays < 1 || b.EventMaxRows < 100 {
		return errors.New("invalid resource limits")
	}
	if b.ACMECA != "" {
		u, e := url.Parse(b.ACMECA)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("acme_ca must be an HTTPS URL")
		}
	}
	return nil
}

type Bundle struct {
	Sites    []Site   `json:"sites"`
	Security Security `json:"security"`
}
type Site struct {
	ID                  string        `json:"id"`
	Name                string        `json:"name"`
	Enabled             bool          `json:"enabled"`
	Domains             []string      `json:"domains"`
	HTTPS               bool          `json:"https"`
	RedirectHTTP        bool          `json:"redirect_http"`
	DNSCredential       string        `json:"dns_credential"`
	Upstreams           []Upstream    `json:"upstreams"`
	Routes              []RoutePolicy `json:"routes"`
	MaxConnectionsPerIP int           `json:"max_connections_per_ip"`
	WebSocketOrigins    []string      `json:"websocket_origins"`
}
type Upstream struct {
	URL        string `json:"url"`
	Weight     int    `json:"weight"`
	HealthPath string `json:"health_path"`
}

// Reject unsupported persisted schemas as well as unsupported API fields.
// In particular, an old Bot policy must never be silently discarded on startup.
func (s *Site) UnmarshalJSON(raw []byte) error {
	type siteData Site
	var next siteData
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&next); err != nil {
		return fmt.Errorf("unsupported site configuration: %w", err)
	}
	*s = Site(next)
	return nil
}

type ManagedPolicy struct {
	Mode       string      `json:"mode"`
	Paranoia   int         `json:"paranoia"`
	Threshold  int         `json:"threshold"`
	Exclusions []Exclusion `json:"exclusions"`
}
type Exclusion struct {
	Scope      Scope  `json:"scope"`
	RuleID     int    `json:"rule_id"`
	PathPrefix string `json:"path_prefix"`
	Target     string `json:"target"`
}
type CustomRule struct {
	Scope      Scope             `json:"scope"`
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Enabled    bool              `json:"enabled"`
	Priority   int               `json:"priority"`
	Expression string            `json:"expression"`
	Action     string            `json:"action"`
	Skip       []string          `json:"skip"`
	Challenge  *ChallengeOptions `json:"challenge,omitempty"`
}
type ChallengeOptions struct {
	WorkFactor       int `json:"work_factor"`
	ClearanceSeconds int `json:"clearance_seconds"`
}

func DefaultChallenge() ChallengeOptions {
	return ChallengeOptions{WorkFactor: 5000, ClearanceSeconds: 1800}
}

func IsChallengeAction(action string) bool {
	return action == "managed_challenge" || action == "non_interactive_challenge" || action == "interactive_challenge"
}

type RateLimitPolicy struct {
	Scope             Scope   `json:"scope"`
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Enabled           bool    `json:"enabled"`
	Expression        string  `json:"expression"`
	Key               string  `json:"key"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
	BanSeconds        int     `json:"ban_seconds"`
}
type RoutePolicy struct {
	PathPrefix         string   `json:"path_prefix"`
	Methods            []string `json:"methods"`
	BodyMode           string   `json:"body_mode"`
	MaxBodyBytes       int64    `json:"max_body_bytes"`
	IdleTimeoutSeconds int      `json:"idle_timeout_seconds"`
	MaxDurationSeconds int      `json:"max_duration_seconds"`
	MaxConcurrent      int      `json:"max_concurrent"`
}

func DefaultRoute() RoutePolicy {
	return RoutePolicy{PathPrefix: "/", BodyMode: "inspect", MaxBodyBytes: 8 * MiB, IdleTimeoutSeconds: 300, MaxConcurrent: 256}
}
func DefaultSite() Site {
	return Site{Enabled: true, HTTPS: true, RedirectHTTP: true, DNSCredential: "cloudflare", Routes: []RoutePolicy{DefaultRoute()}, MaxConnectionsPerIP: 32}
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var targetPattern = regexp.MustCompile(`^(?:ARGS|ARGS_NAMES|REQUEST_HEADERS|REQUEST_COOKIES):[A-Za-z0-9_.\[\]-]{1,128}$`)

func ValidID(s string) bool { return idPattern.MatchString(s) }
func ValidDomain(s string, wildcard bool) bool {
	if wildcard && strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	if s != strings.ToLower(s) || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !labelPattern.MatchString(l) {
			return false
		}
	}
	return true
}
func Host(s string) string {
	if h, _, e := net.SplitHostPort(s); e == nil {
		s = h
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// CanonicalPath is used consistently for routing and CEL path predicates.
// The original escaped target is still forwarded and exposed as request.raw_path.
func CanonicalPath(s string) string {
	clean := path.Clean(s)
	if clean == "." {
		clean = "/"
	}
	if strings.HasSuffix(s, "/") && clean != "/" {
		clean += "/"
	}
	return clean
}
func MatchesDomain(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		prefix := strings.TrimSuffix(host, suffix)
		return prefix != host && prefix != "" && !strings.Contains(prefix, ".")
	}
	return false
}

func (b *Bundle) NormalizeAndValidate(boot Bootstrap) error {
	if len(b.Sites) > 200 {
		return errors.New("at most 200 sites are supported")
	}
	ids := map[string]bool{}
	domains := map[string]bool{}
	totalRoutes := 0
	for i := range b.Sites {
		s := &b.Sites[i]
		totalRoutes += len(s.Routes)
		if totalRoutes > 1000 {
			return errors.New("configuration exceeds global policy count limits")
		}
		if !ValidID(s.ID) || ids[s.ID] {
			return fmt.Errorf("invalid or duplicate site id %q", s.ID)
		}
		ids[s.ID] = true
		if len(s.Name) > 128 || len(s.Domains) == 0 || len(s.Domains) > 100 {
			return fmt.Errorf("site %s: invalid name or domains", s.ID)
		}
		for _, d := range s.Domains {
			if !ValidDomain(d, true) || domains[d] || MatchesDomain(d, boot.AdminDomain) {
				return fmt.Errorf("invalid, duplicate or reserved domain %q", d)
			}
			domains[d] = true
			if len(domains) > 2000 {
				return errors.New("at most 2000 domain names are supported")
			}
		}
		if s.RedirectHTTP && !s.HTTPS {
			return errors.New("HTTP redirect requires HTTPS")
		}
		if s.DNSCredential == "" {
			s.DNSCredential = "cloudflare"
		}
		if !ValidID(s.DNSCredential) {
			return errors.New("invalid DNS credential name")
		}
		if len(s.Upstreams) == 0 || len(s.Upstreams) > 32 {
			return errors.New("each site requires 1-32 upstreams")
		}
		for j := range s.Upstreams {
			u := &s.Upstreams[j]
			p, e := url.Parse(u.URL)
			if e != nil || p.Host == "" || (p.Scheme != "http" && p.Scheme != "https") || p.User != nil || p.RawQuery != "" || p.Fragment != "" || p.Path != "" && p.Path != "/" {
				return fmt.Errorf("invalid upstream URL %q: use an http(s) origin without a path", u.URL)
			}
			if u.Weight == 0 {
				u.Weight = 1
			}
			if u.Weight < 1 || u.Weight > 100 {
				return errors.New("weight must be 1-100")
			}
			if u.HealthPath != "" && (!strings.HasPrefix(u.HealthPath, "/") || strings.HasPrefix(u.HealthPath, "//") || strings.ContainsAny(u.HealthPath, "\r\n")) {
				return errors.New("invalid health path")
			}
		}
		if len(s.Routes) > 100 {
			return errors.New("too many routes")
		}
		if len(s.Routes) == 0 {
			s.Routes = []RoutePolicy{DefaultRoute()}
		}
		for j := range s.Routes {
			r := &s.Routes[j]
			if !strings.HasPrefix(r.PathPrefix, "/") || strings.ContainsAny(r.PathPrefix, "\r\n\\") || len(r.PathPrefix) > 1024 {
				return errors.New("invalid route prefix")
			}
			if r.BodyMode == "" {
				r.BodyMode = "inspect"
			}
			if r.BodyMode != "inspect" && r.BodyMode != "stream" {
				return errors.New("invalid body mode")
			}
			if r.MaxBodyBytes == 0 {
				if r.BodyMode == "stream" {
					return errors.New("stream routes require explicit max_body_bytes")
				}
				r.MaxBodyBytes = 8 * MiB
			}
			if r.MaxBodyBytes < 1 || r.MaxBodyBytes > 1<<40 || r.BodyMode == "inspect" && r.MaxBodyBytes > boot.BodyBudgetBytes/3 {
				return errors.New("body limit exceeds resource budget")
			}
			if r.IdleTimeoutSeconds == 0 {
				r.IdleTimeoutSeconds = 300
			}
			if r.MaxConcurrent == 0 {
				r.MaxConcurrent = 256
			}
			if r.IdleTimeoutSeconds < 1 || r.IdleTimeoutSeconds > 86400 || r.MaxConcurrent < 1 || r.MaxConcurrent > 8192 || r.MaxDurationSeconds < 0 || r.MaxDurationSeconds > 86400 {
				return errors.New("invalid route resource limits")
			}
			if r.BodyMode == "stream" && r.MaxDurationSeconds == 0 {
				return errors.New("stream routes require an explicit maximum duration")
			}
			for _, method := range r.Methods {
				if !regexp.MustCompile(`^[A-Z]{1,20}$`).MatchString(method) {
					return errors.New("invalid method")
				}
			}
		}
		sort.SliceStable(s.Routes, func(a, b int) bool { return len(s.Routes[a].PathPrefix) > len(s.Routes[b].PathPrefix) })
		if s.MaxConnectionsPerIP == 0 {
			s.MaxConnectionsPerIP = 32
		}
		if s.MaxConnectionsPerIP < 1 || s.MaxConnectionsPerIP > 8192 {
			return errors.New("invalid per-IP connection limit")
		}
		for _, o := range s.WebSocketOrigins {
			u, e := url.Parse(o)
			if e != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
				return errors.New("invalid WebSocket origin")
			}
		}

	}
	return b.Security.NormalizeAndValidate(ids)
}

func (s Site) Route(path, method string) RoutePolicy {
	for _, r := range s.Routes {
		if strings.HasPrefix(path, r.PathPrefix) {
			if len(r.Methods) == 0 {
				return r
			}
			for _, m := range r.Methods {
				if m == method {
					return r
				}
			}
		}
	}
	return DefaultRoute()
}
