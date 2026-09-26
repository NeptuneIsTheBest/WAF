package tlsmgr

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
	"waf/internal/config"
	"waf/internal/store"
)

type Credential struct {
	APIToken  string `json:"api_token"`
	ZoneToken string `json:"zone_token,omitempty"`
}
type Status struct {
	Domain     string `json:"domain"`
	Credential string `json:"credential"`
	State      string `json:"state"`
	Expires    string `json:"expires,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	LastEvent  string `json:"last_event,omitempty"`
	Staging    bool   `json:"staging"`
}
type Manager struct {
	boot          config.Bootstrap
	store         *store.Store
	cache         *certmagic.Cache
	mu            sync.RWMutex
	syncMu        sync.Mutex
	configs       map[string]*certmagic.Config
	domains       map[string]string
	status        map[string]Status
	ctx           context.Context
	cancel        context.CancelFunc
	logger        *zap.Logger
	issuerFactory func(*certmagic.Config, Credential) certmagic.Issuer
}

func New(boot config.Bootstrap, s *store.Store) *Manager {
	return newManager(boot, s, 0)
}
func newManager(boot config.Bootstrap, s *store.Store, renewInterval time.Duration) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	logger, _ := zap.NewProduction()
	m := &Manager{boot: boot, store: s, configs: map[string]*certmagic.Config{}, domains: map[string]string{}, status: map[string]Status{}, ctx: ctx, cancel: cancel, logger: logger}
	m.cache = certmagic.NewCache(certmagic.CacheOptions{Capacity: 4096, Logger: logger, RenewCheckInterval: renewInterval, GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		for _, name := range cert.Names {
			if ref, ok := m.domains[name]; ok {
				if c := m.configs[ref]; c != nil {
					return c, nil
				}
			}
		}
		return nil, errors.New("certificate is no longer configured")
	}})
	return m
}
func ParseCredential(raw []byte) (Credential, error) {
	var c Credential
	if e := json.Unmarshal(raw, &c); e != nil {
		return c, e
	}
	if strings.TrimSpace(c.APIToken) == "" || len(c.APIToken) > 4096 || len(c.ZoneToken) > 4096 {
		return c, errors.New("Cloudflare API token is required")
	}
	return c, nil
}
func (m *Manager) desired(b config.Bundle) map[string]string {
	out := map[string]string{m.boot.AdminDomain: "cloudflare"}
	for _, s := range b.Sites {
		if !s.Enabled || !s.HTTPS {
			continue
		}
		for _, d := range s.Domains {
			out[d] = s.DNSCredential
		}
	}
	return out
}
func (m *Manager) Validate(b config.Bundle) error {
	if m.boot.Development {
		return nil
	}
	checked := map[string]bool{}
	for _, name := range m.desired(b) {
		if checked[name] {
			continue
		}
		checked[name] = true
		raw, e := m.store.Secret(name)
		if e != nil {
			return fmt.Errorf("DNS credential %s is missing", name)
		}
		if _, e = ParseCredential(raw); e != nil {
			return fmt.Errorf("invalid DNS credential %s", name)
		}
	}
	return nil
}
func (m *Manager) Sync(b config.Bundle) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	if e := m.Validate(b); e != nil {
		return e
	}
	domains := m.desired(b)
	if m.boot.Development {
		m.mu.Lock()
		m.domains = domains
		m.mu.Unlock()
		return nil
	}
	configs := map[string]*certmagic.Config{}
	for _, ref := range domains {
		if configs[ref] != nil {
			continue
		}
		raw, e := m.store.Secret(ref)
		if e != nil {
			return e
		}
		cred, e := ParseCredential(raw)
		if e != nil {
			return e
		}
		c := certmagic.New(m.cache, certmagic.Config{Storage: &certmagic.FileStorage{Path: filepath.Join(m.boot.DataDir, "certificates")}, Logger: m.logger, OnEvent: m.onEvent(cred)})
		issuer := certmagic.ACMEIssuer{Email: m.boot.ACMEEmail, Agreed: true, DisableHTTPChallenge: true, DisableTLSALPNChallenge: true, DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: &cloudflare.Provider{APIToken: cred.APIToken, ZoneToken: cred.ZoneToken, HTTPClient: &http.Client{Timeout: 30 * time.Second}}, PropagationTimeout: 2 * time.Minute}}, Logger: m.logger}
		if m.boot.ACMECA != "" {
			issuer.CA = m.boot.ACMECA
		}
		c.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(c, issuer)}
		if m.issuerFactory != nil {
			c.Issuers = []certmagic.Issuer{m.issuerFactory(c, cred)}
		}
		configs[ref] = c
	}
	m.mu.Lock()
	var removed []certmagic.SubjectIssuer
	for domain := range m.domains {
		if _, exists := domains[domain]; !exists {
			removed = append(removed, certmagic.SubjectIssuer{Subject: domain})
		}
	}
	m.domains = domains
	m.configs = configs
	for domain, ref := range domains {
		old := m.status[domain]
		old.Domain = domain
		old.Credential = ref
		old.Staging = strings.Contains(m.boot.ACMECA, "staging")
		if old.State == "" {
			old.State = "pending"
		}
		m.status[domain] = old
	}
	for domain := range m.status {
		if _, ok := domains[domain]; !ok {
			delete(m.status, domain)
		}
	}
	m.mu.Unlock()
	m.cache.RemoveManaged(removed)
	groups := map[string][]string{}
	for domain, ref := range domains {
		groups[ref] = append(groups[ref], domain)
	}
	for ref, names := range groups {
		if e := configs[ref].ManageAsync(m.ctx, names); e != nil {
			return e
		}
	}
	return nil
}
func (m *Manager) onEvent(cred Credential) func(context.Context, string, map[string]any) error {
	return func(_ context.Context, event string, data map[string]any) error {
		domain, _ := data["identifier"].(string)
		if domain == "" {
			return nil
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		s, exists := m.status[domain]
		if !exists {
			return nil
		}
		s.LastEvent = event
		switch event {
		case "cert_obtaining", "cert_renewing":
			s.State = "pending"
		case "cert_obtained", "cert_renewed":
			s.State = "active"
			s.LastError = ""
		case "cert_failed":
			s.State = "error"
			msg := fmt.Sprint(data["error"])
			for _, secret := range []string{cred.APIToken, cred.ZoneToken} {
				if secret != "" {
					msg = strings.ReplaceAll(msg, secret, "[redacted]")
				}
			}
			if len(msg) > 512 {
				msg = msg[:512]
			}
			s.LastError = msg
		}
		m.status[domain] = s
		return nil
	}
}
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(hello.ServerName)
	m.mu.RLock()
	ref, ok := m.domains[name]
	if !ok {
		for d, r := range m.domains {
			if config.MatchesDomain(d, name) {
				ref = r
				ok = true
				break
			}
		}
	}
	c := m.configs[ref]
	m.mu.RUnlock()
	if !ok || c == nil {
		return nil, errors.New("unconfigured TLS server name")
	}
	ctx := hello.Context()
	if ctx == nil {
		ctx = m.ctx
	}
	return c.GetCertificateWithContext(ctx, hello)
}
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: m.GetCertificate}
}
func (m *Manager) Statuses() []Status {
	m.mu.RLock()
	out := make([]Status, 0, len(m.domains))
	for d, ref := range m.domains {
		s := m.status[d]
		s.Domain = d
		s.Credential = ref
		if m.boot.Development {
			s.State = "development"
		}
		out = append(out, s)
	}
	m.mu.RUnlock()
	for i := range out {
		for _, cert := range m.cache.AllMatchingCertificates(out[i].Domain) {
			if cert.Leaf != nil {
				out[i].Expires = cert.Leaf.NotAfter.UTC().Format(time.RFC3339)
				if time.Now().Before(cert.Leaf.NotAfter) {
					out[i].State = "active"
				} else {
					out[i].State = "expired"
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
func (m *Manager) Ready() bool {
	if m.boot.Development {
		return true
	}
	for _, s := range m.Statuses() {
		if s.Domain == m.boot.AdminDomain && s.State == "active" {
			return true
		}
	}
	return false
}
func (m *Manager) Close() { m.cancel(); m.cache.Stop(); m.logger.Sync() }
