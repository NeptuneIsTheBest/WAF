package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func securityFixture() Bundle {
	b := DefaultBundle()
	for _, id := range []string{"one", "two"} {
		s := DefaultSite()
		s.ID = id
		s.Domains = []string{id + ".example.com"}
		s.Upstreams = []Upstream{{URL: "http://127.0.0.1:3000"}}
		b.Sites = append(b.Sites, s)
	}
	return b
}
func TestGlobalSecurityScopesAndReferences(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Bundle)
	}{
		{"empty selection", func(b *Bundle) { b.Security.CustomRules[0].Scope = Scope{Mode: "sites"} }},
		{"unknown site", func(b *Bundle) { b.Security.CustomRules[0].Scope = Scope{Mode: "sites", SiteIDs: []string{"missing"}} }},
		{"all with ids", func(b *Bundle) { b.Security.CustomRules[0].Scope = Scope{Mode: "all", SiteIDs: []string{"one"}} }},
		{"duplicate rule", func(b *Bundle) { b.Security.CustomRules = append(b.Security.CustomRules, b.Security.CustomRules[0]) }},
		{"duplicate rate", func(b *Bundle) { b.Security.RateLimits = append(b.Security.RateLimits, b.Security.RateLimits[0]) }},
		{"missing skip target", func(b *Bundle) {
			b.Security.CustomRules[0].Action = "skip"
			b.Security.CustomRules[0].Skip = []string{"rate:missing"}
		}},
		{"deleted site", func(b *Bundle) {
			b.Security.RateLimits[0].Scope = Scope{Mode: "sites", SiteIDs: []string{"one"}}
			b.Sites = b.Sites[1:]
		}},
		{"reserved override", func(b *Bundle) { b.Security.Managed.Overrides = []ManagedOverride{{ID: "default"}} }},
		{"exclusion reference", func(b *Bundle) {
			b.Security.Managed.Default.Exclusions = []Exclusion{{RuleID: 913100, Scope: Scope{Mode: "sites", SiteIDs: []string{"missing"}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := securityFixture()
			b.Security.CustomRules = []CustomRule{{ID: "block", Action: "block", Expression: "true"}}
			b.Security.RateLimits = []RateLimitPolicy{{ID: "limit", Key: "ip", RequestsPerSecond: 1, Burst: 1}}
			tc.edit(&b)
			if b.NormalizeAndValidate(DefaultBootstrap()) == nil {
				t.Fatal("invalid global configuration accepted")
			}
		})
	}
	b := securityFixture()
	b.Security.CustomRules = []CustomRule{{ID: "shared", Action: "block", Scope: Scope{Mode: "sites", SiteIDs: []string{"one", "two"}}}}
	if err := b.NormalizeAndValidate(DefaultBootstrap()); err != nil {
		t.Fatal(err)
	}
	if b.Security.Managed.Default.Mode != "observe" || b.Security.Managed.Default.Paranoia != 1 || b.Security.Managed.Default.Threshold != 5 {
		t.Fatal("defaults")
	}
}
func TestCandidateLimitsUseScopeAndKeepStablePriority(t *testing.T) {
	b := securityFixture()
	for _, site := range b.Sites {
		for i := 0; i < 16; i++ {
			b.Security.CustomRules = append(b.Security.CustomRules, CustomRule{ID: fmt.Sprintf("%s-%d", site.ID, i), Action: "managed_challenge", Scope: Scope{Mode: "sites", SiteIDs: []string{site.ID}}, Priority: 10})
		}
	}
	if err := b.NormalizeAndValidate(DefaultBootstrap()); err != nil {
		t.Fatal(err)
	}
	if b.Security.CustomRules[0].ID != "one-0" || b.Security.CustomRules[16].ID != "two-0" {
		t.Fatal("unstable ordering")
	}
	b.Security.CustomRules = append(b.Security.CustomRules, CustomRule{ID: "global", Action: "interactive_challenge"})
	if b.NormalizeAndValidate(DefaultBootstrap()) == nil {
		t.Fatal("scope allowed challenge limit bypass")
	}
	empty := DefaultBundle()
	empty.Security.CustomRules = []CustomRule{{ID: "before-sites", Action: "block", Expression: "true"}}
	if err := empty.NormalizeAndValidate(DefaultBootstrap()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 201; i++ {
		empty.Security.CustomRules = append(empty.Security.CustomRules, CustomRule{ID: fmt.Sprintf("global-%d", i), Action: "log"})
	}
	if empty.NormalizeAndValidate(DefaultBootstrap()) == nil {
		t.Fatal("unbounded all-site rules before first site")
	}
}
func TestSiteLevelSecurityJSONRejected(t *testing.T) {
	for _, field := range []string{`"rules":[]`, `"rate_limits":[]`, `"managed":{"mode":"block"}`} {
		var b Bundle
		if err := json.Unmarshal([]byte(`{"sites":[{"id":"old",`+field+`}],"security":{}}`), &b); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("legacy field accepted: %s: %v", field, err)
		}
	}
	var b Bundle
	if json.Unmarshal([]byte(`{"sites":[],"security":{"unknown":true}}`), &b) == nil {
		t.Fatal("unknown persisted security field ignored")
	}
}
