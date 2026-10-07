package config

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestReservedDomainAndStreamValidation(t *testing.T) {
	b := DefaultBootstrap()
	b.AdminDomain = "admin.example.com"
	security := DefaultSecurity()
	site := DefaultSite()
	site.ID = "site"
	site.Domains = []string{"*.example.com"}
	site.Upstreams = []Upstream{{URL: "http://127.0.0.1:3000", Weight: 1}}
	bundle := Bundle{Sites: []Site{site}, Security: security}
	if bundle.NormalizeAndValidate(b) == nil {
		t.Fatal("wildcard consumed admin domain")
	}
	site.Domains = []string{"site.example.com"}
	site.Routes = []RoutePolicy{{PathPrefix: "/upload", BodyMode: "stream", MaxBodyBytes: 1024}}
	bundle.Sites[0] = site
	bundle.Security = security
	if bundle.NormalizeAndValidate(b) == nil {
		t.Fatal("unbounded stream duration")
	}
	site.Routes[0].MaxDurationSeconds = 60
	bundle.Sites[0] = site
	bundle.Security = security
	if err := bundle.NormalizeAndValidate(b); err != nil {
		t.Fatal(err)
	}
	security.CustomRules = []CustomRule{{ID: "skip", Enabled: true, Expression: "true", Action: "skip", Skip: []string{"all"}}}
	bundle.Sites[0] = site
	bundle.Security = security
	if bundle.NormalizeAndValidate(b) == nil {
		t.Fatal("unscoped skip")
	}
}
func FuzzDomainMatch(f *testing.F) {
	f.Add("*.example.com", "a.example.com")
	f.Add("*.example.com", "a.b.example.com")
	f.Fuzz(func(t *testing.T, pattern, host string) {
		if !ValidDomain(pattern, true) || !ValidDomain(host, false) {
			return
		}
		if MatchesDomain(pattern, host) && pattern != host && pattern[:2] != "*." {
			t.Fatal("nonwildcard matched another host")
		}
	})
}

func TestChallengeActionsAndSkipTargets(t *testing.T) {
	for _, action := range []string{"block", "log", "skip", "managed_challenge", "non_interactive_challenge", "interactive_challenge"} {
		t.Run(action, func(t *testing.T) {
			security := DefaultSecurity()
			site := DefaultSite()
			site.ID = "site"
			site.Domains = []string{"site.example.com"}
			site.Upstreams = []Upstream{{URL: "http://127.0.0.1:3000", Weight: 1}}
			security.CustomRules = []CustomRule{{ID: "one", Enabled: true, Expression: "true", Action: action}}
			if action == "skip" {
				security.CustomRules[0].Skip = []string{"custom_rules", "rate_limits", "managed"}
			}
			b := Bundle{Sites: []Site{site}, Security: security}
			if err := b.NormalizeAndValidate(DefaultBootstrap()); err != nil {
				t.Fatal(err)
			}
			if IsChallengeAction(action) {
				if *b.Security.CustomRules[0].Challenge != DefaultChallenge() {
					t.Fatal("missing defaults")
				}
				b.Security.CustomRules[0].Challenge.WorkFactor = 999
				if b.NormalizeAndValidate(DefaultBootstrap()) == nil {
					t.Fatal("unbounded work")
				}
			}
		})
	}
	security := DefaultSecurity()
	site := DefaultSite()
	site.ID = "site"
	site.Domains = []string{"site.example.com"}
	site.Upstreams = []Upstream{{URL: "http://127.0.0.1:3000", Weight: 1}}
	for _, rule := range []CustomRule{{ID: "one", Action: "challenge"}, {ID: "one", Action: "skip", Skip: []string{"bot"}}, {ID: "one", Action: "skip", Skip: []string{"rate:missing"}}, {ID: "one", Action: "skip", Skip: []string{"rule:missing"}}, {ID: "one", Action: "block", Challenge: &ChallengeOptions{WorkFactor: 1000, ClearanceSeconds: 60}}} {
		security.CustomRules = []CustomRule{rule}
		b := Bundle{Sites: []Site{site}, Security: security}
		if b.NormalizeAndValidate(DefaultBootstrap()) == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
	security.CustomRules = nil
	for i := 0; i < 17; i++ {
		security.CustomRules = append(security.CustomRules, CustomRule{ID: fmt.Sprintf("rule%d", i), Action: []string{"managed_challenge", "non_interactive_challenge", "interactive_challenge"}[i%3]})
	}
	b := Bundle{Sites: []Site{site}, Security: security}
	if b.NormalizeAndValidate(DefaultBootstrap()) == nil {
		t.Fatal("challenge count bypass")
	}
}

func TestLegacyConfigurationIsRejected(t *testing.T) {
	for _, raw := range []string{`{"id":"site","bot":{"enabled":true}}`, `{"id":"site","routes":[{"path_prefix":"/","allow_challenge":true}]}`} {
		var site Site
		if json.Unmarshal([]byte(raw), &site) == nil {
			t.Fatal("unsupported configuration silently changed protection")
		}
	}
}
