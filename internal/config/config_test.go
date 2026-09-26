package config

import "testing"

func TestReservedDomainAndStreamValidation(t *testing.T) {
	b := DefaultBootstrap()
	b.AdminDomain = "admin.example.com"
	site := DefaultSite()
	site.ID = "site"
	site.Domains = []string{"*.example.com"}
	site.Upstreams = []Upstream{{URL: "http://127.0.0.1:3000", Weight: 1}}
	bundle := Bundle{Sites: []Site{site}}
	if bundle.NormalizeAndValidate(b) == nil {
		t.Fatal("wildcard consumed admin domain")
	}
	site.Domains = []string{"site.example.com"}
	site.Routes = []RoutePolicy{{PathPrefix: "/upload", BodyMode: "stream", MaxBodyBytes: 1024}}
	bundle.Sites[0] = site
	if bundle.NormalizeAndValidate(b) == nil {
		t.Fatal("unbounded stream duration")
	}
	site.Routes[0].MaxDurationSeconds = 60
	bundle.Sites[0] = site
	if err := bundle.NormalizeAndValidate(b); err != nil {
		t.Fatal(err)
	}
	site.Rules = []CustomRule{{ID: "skip", Enabled: true, Expression: "true", Action: "skip", Skip: []string{"all"}}}
	bundle.Sites[0] = site
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
