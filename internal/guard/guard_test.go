package guard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTrustedProxyChain(t *testing.T) {
	trusted := ParseCIDRs([]string{"10.0.0.0/8"})
	for _, tc := range []struct{ remote, header, want string }{{"192.0.2.9:123", "1.1.1.1", "192.0.2.9"}, {"10.0.0.2:123", "1.1.1.1, 192.0.2.5, 10.0.0.1", "192.0.2.5"}, {"10.0.0.2:123", "malformed", "10.0.0.2"}} {
		r := httptest.NewRequest("GET", "http://example.com", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-For", tc.header)
		if got := ClientIP(r, trusted).String(); got != tc.want {
			t.Errorf("got %s want %s", got, tc.want)
		}
	}
}
func TestLimitsBanCapacityAndRelease(t *testing.T) {
	l := NewLimits(1)
	now := time.Unix(1000, 0)
	if !l.allowAt("one", 1, 1, time.Minute, now) || l.allowAt("one", 1, 1, time.Minute, now) {
		t.Fatal("burst limit")
	}
	if l.allowAt("one", 1, 1, time.Minute, now.Add(30*time.Second)) {
		t.Fatal("ban bypass")
	}
	if !l.allowAt("one", 1, 1, time.Minute, now.Add(61*time.Second)) {
		t.Fatal("ban expiry")
	}
	if l.allowAt("two", 1, 1, 0, now) {
		t.Fatal("capacity evicted active entry")
	}
	release, ok := l.Acquire("conn", 1)
	if !ok {
		t.Fatal("acquire")
	}
	if _, ok = l.Acquire("conn", 1); ok {
		t.Fatal("connection cap")
	}
	release()
	release()
	if done, ok := l.Acquire("conn", 1); !ok {
		t.Fatal("release")
	} else {
		done()
	}
}
func solve(t *testing.T, c *Challenge, token, site, ip string, rev int64, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	answer := ""
	for n := 0; n < 1<<20; n++ {
		s := strconv.Itoa(n)
		if ValidProof(token, s, 8) {
			answer = s
			break
		}
	}
	if answer == "" {
		t.Fatal("no proof")
	}
	raw, _ := json.Marshal(map[string]string{"ticket": token, "answer": answer})
	r := httptest.NewRequest("POST", "http://site.example.com/.waf/challenge/solve", bytes.NewReader(raw))
	r.Header.Set("User-Agent", "browser")
	r.Header.Set("Origin", "http://site.example.com")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	c.Serve(w, r, site, ip, rev)
	return w
}
func TestChallengeBindingReplayAndClearance(t *testing.T) {
	c := NewChallenge(bytes.Repeat([]byte{1}, 32), true)
	r := httptest.NewRequest("GET", "http://site.example.com/protected", nil)
	r.Header.Set("User-Agent", "browser")
	token := c.Issue(r, "site", "rule:protect", "192.0.2.1", 3, 8, 1800)
	w := solve(t, c, token, "site", "192.0.2.1", 3, nil)
	if w.Code != 200 {
		t.Fatalf("solve: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	r.AddCookie(cookie)
	if !c.Cleared(r, "site", "rule:protect", "192.0.2.1", 3) {
		t.Fatal("valid clearance rejected")
	}
	if c.Cleared(r, "site", "other", "192.0.2.1", 3) || c.Cleared(r, "site", "rule:protect", "192.0.2.2", 3) || c.Cleared(r, "site", "rule:protect", "192.0.2.1", 4) {
		t.Fatal("clearance scope bypass")
	}
	if w = solve(t, c, token, "site", "192.0.2.1", 3, nil); w.Code != 403 {
		t.Fatal("proof replay")
	}
	second := c.Issue(r, "site", "rule:second", "192.0.2.1", 3, 8, 1800)
	w = solve(t, c, second, "site", "192.0.2.1", 3, cookie)
	if w.Code != 200 {
		t.Fatalf("second challenge: %d", w.Code)
	}
	r.Header.Del("Cookie")
	r.AddCookie(w.Result().Cookies()[0])
	if !c.Cleared(r, "site", "rule:protect", "192.0.2.1", 3) || !c.Cleared(r, "site", "rule:second", "192.0.2.1", 3) {
		t.Fatal("solving a second challenge discarded the first scope")
	}
	for _, target := range []string{"//evil.test", "/\\evil.test", "https://evil.test", "/\nLocation:evil"} {
		if validReturn(target) {
			t.Fatalf("unsafe redirect: %q", target)
		}
	}
	w = httptest.NewRecorder()
	r.Header.Set("Accept", "application/json")
	c.Deny(w, r, "site", "new", "192.0.2.1", 3, 8, 1800, true)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "challenge_required") {
		t.Fatal("API unexpectedly got HTML challenge")
	}
}
