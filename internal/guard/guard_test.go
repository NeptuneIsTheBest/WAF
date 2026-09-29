package guard

import (
	"net/http/httptest"
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
