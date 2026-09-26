package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"waf/internal/config"
	"waf/internal/secure"
	"waf/internal/store"
)

type testIssuer struct {
	key   *ecdsa.PrivateKey
	calls atomic.Int64
	fail  atomic.Bool
	renew chan struct{}
}

func (i *testIssuer) IssuerKey() string { return "local-test-issuer" }
func (i *testIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	n := i.calls.Add(1)
	if i.fail.Load() {
		return nil, errors.New("simulated issuer failure")
	}
	if n == 2 {
		select {
		case <-i.renew:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	expiry := time.Now().Add(time.Hour)
	if n == 1 {
		expiry = time.Now().Add(time.Minute)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, i.key)
	if err != nil {
		return nil, err
	}
	return &certmagic.IssuedCertificate{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
func TestAutomaticRenewalAndFailureRetainsCertificate(t *testing.T) {
	boot := config.DefaultBootstrap()
	boot.AdminDomain = "admin.example.com"
	boot.DataDir = t.TempDir()
	boot.MasterKeyFile = filepath.Join(boot.DataDir, "master.key")
	boot.ACMEEmail = "test@example.com"
	if err := secure.CreateKey(boot.MasterKeyFile); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(boot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.PutSecret("cloudflare", []byte(`{"api_token":"test-token-never-sent"}`), "test"); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuer := &testIssuer{key: key, renew: make(chan struct{})}
	m := newManager(boot, s, 30*time.Millisecond)
	defer m.Close()
	m.issuerFactory = func(*certmagic.Config, Credential) certmagic.Issuer { return issuer }
	if err = m.Sync(config.Bundle{}); err != nil {
		t.Fatal(err)
	}
	clientConn, peerConn := net.Pipe()
	defer clientConn.Close()
	defer peerConn.Close()
	hello := &tls.ClientHelloInfo{ServerName: boot.AdminDomain, Conn: clientConn, SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256}}
	deadline := time.Now().Add(5 * time.Second)
	var first *tls.Certificate
	for time.Now().Before(deadline) {
		first, err = m.GetCertificate(hello)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("initial certificate serial")
	}
	if _, err = m.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("unknown SNI accepted")
	}
	close(issuer.renew)
	var renewed *tls.Certificate
	for time.Now().Before(deadline) {
		renewed, err = m.GetCertificate(hello)
		if err == nil && renewed.Leaf.SerialNumber.Int64() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || renewed.Leaf.SerialNumber.Int64() < 2 {
		t.Fatal("automatic renewal did not hot-load")
	}
	issuer.fail.Store(true)
	m.mu.RLock()
	cfg := m.configs["cloudflare"]
	m.mu.RUnlock()
	if err = cfg.RenewCertSync(context.Background(), boot.AdminDomain, true); err == nil {
		t.Fatal("issuer failure not reported")
	}
	current, err := m.GetCertificate(hello)
	if err != nil || current.Leaf.SerialNumber.Cmp(renewed.Leaf.SerialNumber) != 0 {
		t.Fatal("valid certificate lost on renewal failure")
	}
}
func TestCredentialsAndEventRedaction(t *testing.T) {
	for _, raw := range []string{`{}`, `{"api_token":""}`, `not-json`} {
		if _, err := ParseCredential([]byte(raw)); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	m := &Manager{status: map[string]Status{"site.example.com": {Domain: "site.example.com"}}}
	m.onEvent(Credential{APIToken: "sensitive"})(context.Background(), "cert_failed", map[string]any{"identifier": "site.example.com", "error": "failed token sensitive"})
	if m.status["site.example.com"].LastError != "failed token [redacted]" {
		t.Fatal("secret leaked into certificate status")
	}
}
