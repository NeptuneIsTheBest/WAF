package guard

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	tokens                      float64
	updated, timeUsed, banUntil time.Time
}
type Limits struct {
	mu        sync.Mutex
	buckets   map[string]bucket
	counts    map[string]int
	max       int
	lastPrune time.Time
}

func NewLimits(max int) *Limits {
	return &Limits{buckets: map[string]bucket{}, counts: map[string]int{}, max: max, lastPrune: time.Now()}
}

// Capacity exhaustion rejects new keys instead of evicting live bans or counters.
func (l *Limits) Allow(key string, rate float64, burst int, ban time.Duration) bool {
	return l.allowAt(key, rate, burst, ban, time.Now())
}
func (l *Limits) allowAt(key string, rate float64, burst int, ban time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastPrune) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.timeUsed) > 10*time.Minute && now.After(b.banUntil) {
				delete(l.buckets, k)
			}
		}
		l.lastPrune = now
	}
	b, exists := l.buckets[key]
	if !exists {
		if len(l.buckets) >= l.max {
			return false
		}
		b = bucket{tokens: float64(burst), updated: now}
	}
	elapsed := now.Sub(b.updated).Seconds()
	b.tokens = min(float64(burst), b.tokens+elapsed*rate)
	b.updated = now
	b.timeUsed = now
	ok := !now.Before(b.banUntil) && b.tokens >= 1
	if ok {
		b.tokens--
	} else if !now.Before(b.banUntil) && ban > 0 {
		b.banUntil = now.Add(ban)
	}
	l.buckets[key] = b
	return ok
}
func (l *Limits) Acquire(key string, limit int) (func(), bool) {
	l.mu.Lock()
	if l.counts[key] >= limit || len(l.counts) >= l.max && l.counts[key] == 0 {
		l.mu.Unlock()
		return nil, false
	}
	l.counts[key]++
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.counts[key]--
			if l.counts[key] == 0 {
				delete(l.counts, key)
			}
		})
	}, true
}

type Budget struct {
	mu        sync.Mutex
	used, max int64
}

func NewBudget(max int64) *Budget { return &Budget{max: max} }
func (b *Budget) Reserve(n int64) (func(), bool) {
	b.mu.Lock()
	if n < 0 || n > b.max-b.used {
		b.mu.Unlock()
		return nil, false
	}
	b.used += n
	b.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { b.mu.Lock(); b.used -= n; b.mu.Unlock() }) }, true
}
func (b *Budget) Used() int64 { b.mu.Lock(); defer b.mu.Unlock(); return b.used }
func ParseCIDRs(raw []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, e := netip.ParsePrefix(s)
		if e == nil {
			out = append(out, p)
		}
	}
	return out
}
func InCIDRs(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func Peer(remote string) netip.Addr {
	h, _, e := net.SplitHostPort(remote)
	if e != nil {
		h = remote
	}
	a, _ := netip.ParseAddr(h)
	return a.Unmap()
}
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := Peer(r.RemoteAddr)
	if !InCIDRs(peer, trusted) {
		return peer
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer
	}
	parts := strings.Split(strings.Join(values, ","), ",")
	if len(parts) > 32 {
		return peer
	}
	current := peer
	for i := len(parts) - 1; i >= 0; i-- {
		if !InCIDRs(current, trusted) {
			return current
		}
		a, e := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if e != nil {
			return peer
		}
		current = a.Unmap()
	}
	return current
}
