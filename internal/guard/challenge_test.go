package guard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"waf/internal/config"
)

func challengeFixture() (*Challenge, *http.Request) {
	c := NewChallenge(bytes.Repeat([]byte{1}, 32), true)
	c.counter = func() (int, error) { return 7, nil }
	r := httptest.NewRequest("GET", "http://site.example.com/protected?q=secret", nil)
	r.Header.Set("User-Agent", "browser")
	r.Header.Set("Accept", "text/html")
	return c, r
}
func testTicket(c *Challenge, r *http.Request, scope string, seconds int) string {
	return c.Issue(r, "site", scope, "192.0.2.1", 3, "managed_challenge", NonInteractive, config.ChallengeOptions{WorkFactor: 1000, ClearanceSeconds: seconds})
}
func testProof(t *testing.T, c *Challenge, token string) altcha.Payload {
	t.Helper()
	r := httptest.NewRequest("GET", "http://site.example.com"+ChallengePath+"/puzzle?ticket="+url.QueryEscape(token), nil)
	r.Header.Set("User-Agent", "browser")
	w := httptest.NewRecorder()
	c.Serve(w, r, "site", "192.0.2.1", 3)
	if w.Code != 200 {
		t.Fatalf("puzzle: %d %s", w.Code, w.Body.String())
	}
	var puzzle altcha.Challenge
	if err := json.Unmarshal(w.Body.Bytes(), &puzzle); err != nil {
		t.Fatal(err)
	}
	solution, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: puzzle, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil {
		t.Fatal(err)
	}
	return altcha.Payload{Challenge: puzzle, Solution: *solution}
}
func proofRequest(token string, proof altcha.Payload, cookie *http.Cookie) *http.Request {
	payload, _ := json.Marshal(proof)
	raw, _ := json.Marshal(map[string]string{"ticket": token, "payload": base64.StdEncoding.EncodeToString(payload)})
	r := httptest.NewRequest("POST", "http://site.example.com"+ChallengePath+"/solve", bytes.NewReader(raw))
	r.Header.Set("User-Agent", "browser")
	r.Header.Set("Origin", "http://site.example.com")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}
func redeem(c *Challenge, token string, proof altcha.Payload, cookie *http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c.Serve(w, proofRequest(token, proof, cookie), "site", "192.0.2.1", 3)
	return w
}
func TestChallengeBindingReplayAndClearance(t *testing.T) {
	c, r := challengeFixture()
	token := testTicket(c, r, "protect", 1800)
	proof := testProof(t, c, token)
	for _, tc := range []struct {
		name, site, ip string
		rev            int64
		change         func(*http.Request)
	}{
		{"site", "other", "192.0.2.1", 3, nil}, {"ip", "site", "192.0.2.2", 3, nil}, {"revision", "site", "192.0.2.1", 4, nil},
		{"host", "site", "192.0.2.1", 3, func(r *http.Request) { r.Host = "other.example.com"; r.Header.Del("Origin") }},
		{"user_agent", "site", "192.0.2.1", 3, func(r *http.Request) { r.Header.Set("User-Agent", "other") }},
		{"origin", "site", "192.0.2.1", 3, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := proofRequest(token, proof, nil)
			if tc.change != nil {
				tc.change(req)
			}
			w := httptest.NewRecorder()
			c.Serve(w, req, tc.site, tc.ip, tc.rev)
			if w.Code != 403 {
				t.Fatalf("binding accepted: %d", w.Code)
			}
		})
	}
	w := redeem(c, token, proof, nil)
	if w.Code != 200 {
		t.Fatalf("solve: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	r.AddCookie(cookie)
	if !c.Cleared(r, "site", "protect", "192.0.2.1", 3) || c.Cleared(r, "site", "other", "192.0.2.1", 3) || c.Cleared(r, "site", "protect", "192.0.2.2", 3) {
		t.Fatal("clearance binding")
	}
	if strings.Contains(cookie.Value, "secret") || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe cookie")
	}
	if w = redeem(c, token, proof, nil); w.Code != 403 {
		t.Fatal("proof replay")
	}
	for _, target := range []string{"//evil.test", "/\\evil.test", "https://evil.test", "/\nLocation:evil"} {
		if validReturn(target) {
			t.Fatalf("unsafe redirect: %q", target)
		}
	}
}
func TestIndependentClearanceExpiry(t *testing.T) {
	c, r := challengeFixture()
	now := time.Now().Truncate(time.Second)
	c.now = func() time.Time { return now }
	one := testTicket(c, r, "short", 60)
	w := redeem(c, one, testProof(t, c, one), nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	now = now.Add(30 * time.Second)
	two := testTicket(c, r, "long", 1800)
	w = redeem(c, two, testProof(t, c, two), cookie)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie = w.Result().Cookies()[0]
	r.AddCookie(cookie)
	if !c.Cleared(r, "site", "short", "192.0.2.1", 3) || !c.Cleared(r, "site", "long", "192.0.2.1", 3) {
		t.Fatal("lost scope")
	}
	now = now.Add(31 * time.Second)
	if c.Cleared(r, "site", "short", "192.0.2.1", 3) || !c.Cleared(r, "site", "long", "192.0.2.1", 3) {
		t.Fatal("one rule extended another's expiry")
	}
	// Solving a shorter-lived rule must not shorten the longer cookie's lifetime.
	three := testTicket(c, r, "third", 60)
	w = redeem(c, three, testProof(t, c, three), cookie)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w.Result().Cookies()[0].MaxAge < 1700 {
		t.Fatal("cookie truncated a longer clearance")
	}
}
func TestProofCannotChangeTicketModeOrWork(t *testing.T) {
	for _, change := range []struct {
		name string
		fn   func(*altcha.Payload)
	}{
		{"cost", func(p *altcha.Payload) { p.Challenge.Parameters.Cost = 1 }},
		{"huge_cost", func(p *altcha.Payload) { p.Challenge.Parameters.Cost = 1 << 30 }},
		{"prefix", func(p *altcha.Payload) { p.Challenge.Parameters.KeyPrefix = "" }},
		{"mode", func(p *altcha.Payload) { p.Challenge.Parameters.Data["mode"] = Interactive }},
		{"signature", func(p *altcha.Payload) { p.Challenge.Signature = "invalid" }},
		{"proof", func(p *altcha.Payload) { p.Solution.DerivedKey = strings.Repeat("0", 64) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			c, r := challengeFixture()
			token := testTicket(c, r, "one", 60)
			proof := testProof(t, c, token)
			change.fn(&proof)
			if w := redeem(c, token, proof, nil); w.Code != 403 || len(w.Result().Cookies()) != 0 {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	c, r := challengeFixture()
	one := testTicket(c, r, "one", 60)
	two := testTicket(c, r, "two", 60)
	if redeem(c, two, testProof(t, c, one), nil).Code != 403 {
		t.Fatal("cross-rule proof accepted")
	}
	c.epoch = "restart"
	if redeem(c, one, altcha.Payload{}, nil).Code != 403 {
		t.Fatal("pre-restart ticket accepted")
	}
}
func TestConcurrentRedemptionAndCapacity(t *testing.T) {
	c, r := challengeFixture()
	c.capacity = 1
	token := testTicket(c, r, "one", 60)
	proof := testProof(t, c, token)
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- redeem(c, token, proof, nil).Code }()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 200 {
			success++
		} else if code != 403 {
			t.Fatalf("unexpected status %d", code)
		}
	}
	if success != 1 {
		t.Fatalf("%d concurrent successes", success)
	}
	second := testTicket(c, r, "two", 60)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://site.example.com"+ChallengePath+"?ticket="+url.QueryEscape(second), nil)
	req.Header.Set("User-Agent", "browser")
	c.Serve(w, req, "site", "192.0.2.1", 3)
	if w.Code != 403 {
		t.Fatal("capacity bypass")
	}
	c.now = func() time.Time { return time.Now().Add(3 * time.Minute) }
	if redeem(c, second, proof, nil).Code != 403 {
		t.Fatal("expired ticket accepted")
	}
}
func TestManagedSelection(t *testing.T) {
	c, _ := challengeFixture()
	now := time.Now()
	c.now = func() time.Time { return now }
	for i := 0; i < 120; i++ {
		if c.Mode("site", "one", "ip", "managed_challenge", 3) != NonInteractive {
			t.Fatalf("early escalation at %d", i)
		}
	}
	if c.Mode("site", "one", "ip", "managed_challenge", 3) != Interactive {
		t.Fatal("rate did not escalate")
	}
	now = now.Add(time.Second)
	if c.Mode("site", "one", "ip", "managed_challenge", 3) != NonInteractive {
		t.Fatal("bucket did not refill")
	}
	ticket := Ticket{Site: "site", Scope: "two", Revision: 3}
	for i := 0; i < 3; i++ {
		c.failed(ticket, "ip")
	}
	if c.Mode("site", "two", "ip", "managed_challenge", 3) != Interactive {
		t.Fatal("failures did not escalate")
	}
	if c.Mode("site", "two", "other-ip", "managed_challenge", 3) != NonInteractive || c.Mode("site", "two", "ip", "managed_challenge", 4) != NonInteractive {
		t.Fatal("risk leaked across context")
	}
	if c.Mode("site", "two", "ip", "non_interactive_challenge", 3) != NonInteractive || c.Mode("site", "two", "ip", "interactive_challenge", 3) != Interactive {
		t.Fatal("fixed mode changed")
	}
	now = now.Add(5 * time.Minute)
	if c.Mode("site", "two", "ip", "managed_challenge", 3) != NonInteractive {
		t.Fatal("failure window never expired")
	}
	c.capacity = 1
	c.failed(ticket, "ip")
	if c.Mode("site", "new", "other-ip", "managed_challenge", 3) != Interactive {
		t.Fatal("capacity exhaustion lowered protection")
	}
}
func TestNonNavigationNeverRedirects(t *testing.T) {
	for _, tc := range []struct{ method, accept, upgrade, fetch string }{{"POST", "text/html", "", ""}, {"GET", "application/json", "", ""}, {"GET", "text/event-stream", "", ""}, {"GET", "text/html", "websocket", ""}, {"GET", "text/html", "", "cors"}} {
		c, r := challengeFixture()
		r.Method = tc.method
		r.Header.Set("Accept", tc.accept)
		r.Header.Set("Upgrade", tc.upgrade)
		r.Header.Set("Sec-Fetch-Mode", tc.fetch)
		w := httptest.NewRecorder()
		c.Deny(w, r, "site", "one", "192.0.2.1", 3, "interactive_challenge", Interactive, config.ChallengeOptions{WorkFactor: 1000, ClearanceSeconds: 60})
		if w.Code != 403 || !strings.Contains(w.Body.String(), "challenge_required") {
			t.Fatal("non-navigation got HTML")
		}
		token := testTicket(c, r, "one", 60)
		w = redeem(c, token, testProof(t, c, token), nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "redirect") {
			t.Fatalf("request replayed: %s", w.Body.String())
		}
	}
	c, r := challengeFixture()
	c.development = false
	w := httptest.NewRecorder()
	c.Deny(w, r, "site", "one", "192.0.2.1", 3, "managed_challenge", NonInteractive, config.DefaultChallenge())
	if w.Code != 403 || !strings.Contains(w.Body.String(), "https_required") {
		t.Fatal("insecure production challenge")
	}
}
