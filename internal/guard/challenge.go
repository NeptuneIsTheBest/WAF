package guard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"waf/internal/config"
	"waf/internal/secure"
	"waf/web"
)

const ChallengePath = "/.waf/challenge"
const NonInteractive = "non_interactive"
const Interactive = "interactive"

type ClearanceScope struct {
	Scope   string `json:"scope"`
	Expires int64  `json:"expires"`
}
type Ticket struct {
	Nonce      string           `json:"nonce,omitempty"`
	Site       string           `json:"site"`
	Scope      string           `json:"scope,omitempty"`
	Scopes     []ClearanceScope `json:"scopes,omitempty"`
	Revision   int64            `json:"revision"`
	Host       string           `json:"host"`
	Binding    string           `json:"binding"`
	Expires    int64            `json:"expires"`
	WorkFactor int              `json:"work_factor,omitempty"`
	Clearance  int              `json:"clearance,omitempty"`
	Return     string           `json:"return,omitempty"`
	Navigate   bool             `json:"navigate,omitempty"`
	Epoch      string           `json:"epoch,omitempty"`
	Action     string           `json:"action,omitempty"`
	Mode       string           `json:"mode,omitempty"`
}
type ChallengeResult struct{ Action, RuleID, Mode string }
type Challenge struct {
	key         []byte
	epoch       string
	mu          sync.Mutex
	used        map[string]int64
	failures    map[string][]int64
	lastPrune   time.Time
	capacity    int
	limits      *Limits
	rates       *Limits
	development bool
	now         func() time.Time
	counter     func() (int, error)
}

func NewChallenge(key []byte, development bool) *Challenge {
	return &Challenge{key: key, epoch: secure.Random(16), used: map[string]int64{}, failures: map[string][]int64{}, capacity: 10000, limits: NewLimits(10000), rates: NewLimits(10000), development: development, now: time.Now, counter: func() (int, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(5000))
		if err != nil {
			return 0, err
		}
		return 5000 + int(n.Int64()), nil
	}}
}
func binding(ip, ua string) string { return secure.Digest(ip + "\x00" + ua) }
func riskKey(site, scope, ip string, revision int64) string {
	return site + ":" + scope + ":" + ip + ":" + strconv.FormatInt(revision, 10)
}
func (c *Challenge) pruneLocked(now time.Time) {
	if !c.lastPrune.IsZero() && now.Sub(c.lastPrune) < time.Minute {
		return
	}
	for nonce, expires := range c.used {
		if expires <= now.Unix() {
			delete(c.used, nonce)
		}
	}
	for key, failures := range c.failures {
		if len(failures) == 0 || failures[len(failures)-1] <= now.Add(-5*time.Minute).Unix() {
			delete(c.failures, key)
		}
	}
	c.lastPrune = now
}

// Mode is selected by the server. Client-supplied signals never downgrade it.
func (c *Challenge) Mode(site, scope, ip, action string, revision int64) string {
	if action == "interactive_challenge" {
		return Interactive
	}
	if action != "managed_challenge" {
		return NonInteractive
	}
	now := c.now()
	key := riskKey(site, scope, ip, revision)
	frequent := !c.rates.allowAt(key, 2, 120, 0, now)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	failures := c.failures[key]
	failed := len(failures) >= 3 && failures[len(failures)-3] > now.Add(-5*time.Minute).Unix()
	if frequent || failed || len(c.failures) >= c.capacity {
		return Interactive
	}
	return NonInteractive
}
func (c *Challenge) failed(t Ticket, ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.pruneLocked(now)
	key := riskKey(t.Site, t.Scope, ip, t.Revision)
	values, exists := c.failures[key]
	if !exists && len(c.failures) >= c.capacity {
		return
	}
	values = append(values, now.Unix())
	if len(values) > 3 {
		values = values[len(values)-3:]
	}
	c.failures[key] = values
}
func (c *Challenge) encode(t Ticket, purpose string) string {
	b, _ := json.Marshal(t)
	body := base64.RawURLEncoding.EncodeToString(b)
	return body + "." + secure.Sign(c.key, purpose, body)
}
func (c *Challenge) decode(token, purpose string) (Ticket, error) {
	var t Ticket
	if len(token) > 16384 {
		return t, errors.New("invalid token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !secure.Equal(secure.Sign(c.key, purpose, parts[0]), parts[1]) {
		return t, errors.New("invalid signature")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return t, err
	}
	if err = json.Unmarshal(b, &t); err != nil || t.Expires <= c.now().Unix() {
		return t, errors.New("expired token")
	}
	return t, nil
}
func (c *Challenge) bound(t Ticket, r *http.Request, site, ip string, revision int64) bool {
	return t.Site == site && t.Revision == revision && t.Host == r.Host && secure.Equal(t.Binding, binding(ip, r.UserAgent()))
}
func (c *Challenge) cookieName() string {
	if c.development {
		return "waf_clearance_dev"
	}
	return "__Host-waf_clearance"
}
func (c *Challenge) Cleared(r *http.Request, site, scope, ip string, revision int64) bool {
	cookie, err := r.Cookie(c.cookieName())
	if err != nil {
		return false
	}
	t, err := c.decode(cookie.Value, "clearance")
	if err != nil || !c.bound(t, r, site, ip, revision) {
		return false
	}
	for _, grant := range t.Scopes {
		if grant.Scope == scope && grant.Expires > c.now().Unix() {
			return true
		}
	}
	return false
}
func navigation(r *http.Request) bool {
	return r.Method == http.MethodGet && r.ContentLength <= 0 && len(r.TransferEncoding) == 0 && strings.Contains(r.Header.Get("Accept"), "text/html") && !strings.Contains(r.Header.Get("Accept"), "text/event-stream") && !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && (r.Header.Get("Sec-Fetch-Mode") == "" || r.Header.Get("Sec-Fetch-Mode") == "navigate")
}
func (c *Challenge) Issue(r *http.Request, site, scope, ip string, revision int64, action, mode string, options config.ChallengeOptions) string {
	target := r.URL.RequestURI()
	if !validReturn(target) {
		target = "/"
	}
	return c.encode(Ticket{Nonce: secure.Random(24), Site: site, Scope: scope, Revision: revision, Host: r.Host, Binding: binding(ip, r.UserAgent()), Expires: c.now().Add(2 * time.Minute).Unix(), WorkFactor: options.WorkFactor, Clearance: options.ClearanceSeconds, Return: target, Navigate: navigation(r), Epoch: c.epoch, Action: action, Mode: mode}, "puzzle")
}
func validReturn(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n") {
		return false
	}
	u, err := url.ParseRequestURI(s)
	return err == nil && u.Host == "" && !u.IsAbs()
}
func challengeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func (c *Challenge) Deny(w http.ResponseWriter, r *http.Request, site, scope, ip string, revision int64, action, mode string, options config.ChallengeOptions) {
	w.Header().Set("Cache-Control", "no-store")
	if !c.limits.Allow("issue:"+ip, 3, 20, 0) {
		w.Header().Set("Retry-After", "1")
		challengeError(w, 429, "challenge_rate_limited")
		return
	}
	if r.TLS == nil && !c.development {
		challengeError(w, 403, "https_required")
		return
	}
	token := c.Issue(r, site, scope, ip, revision, action, mode, options)
	if navigation(r) {
		c.Page(w, r, token, 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	json.NewEncoder(w).Encode(map[string]string{"error": "challenge_required", "action": action, "challenge_mode": mode, "challenge_url": ChallengePath + "?ticket=" + url.QueryEscape(token)})
}

var challengeTemplate = template.Must(template.New("challenge").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>浏览器安全验证</title><link rel="stylesheet" href="/.waf/challenge/assets/challenge.css"></head><body><main id="challenge" data-ticket="{{.Token}}" data-mode="{{.Mode}}"><div class="shield" aria-hidden="true">✓</div><h1>浏览器安全验证</h1><p id="status" role="status">{{if eq .Mode "interactive"}}请点击下方复选框完成验证。{{else}}正在验证浏览器，请稍候。{{end}}</p><div id="widget"></div><button id="retry" type="button" hidden>重新验证</button><noscript>此页面需要 JavaScript。请联系网站管理员获取其他访问方式。</noscript></main><script type="module" nonce="{{.Nonce}}" src="/.waf/challenge/assets/challenge.js"></script></body></html>`))

func (c *Challenge) Page(w http.ResponseWriter, r *http.Request, token string, status int) {
	t, err := c.decode(token, "puzzle")
	if err != nil || t.Epoch != c.epoch {
		challengeError(w, 403, "invalid_or_expired_challenge")
		return
	}
	nonce := secure.Random(18)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self'; worker-src 'self' blob:; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.WriteHeader(status)
	challengeTemplate.Execute(w, map[string]any{"Nonce": nonce, "Token": token, "Mode": t.Mode})
}
func (c *Challenge) puzzle(t Ticket, token string) (altcha.Challenge, error) {
	counter, err := c.counter()
	if err != nil {
		return altcha.Challenge{}, err
	}
	expires := time.Unix(t.Expires, 0)
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{Algorithm: "PBKDF2/SHA-256", DeriveKey: altcha.DeriveKeyPBKDF2(), Cost: t.WorkFactor, Counter: &counter, KeyLength: 32, ExpiresAt: &expires, HMACSignatureSecret: secure.Sign(c.key, "altcha", token), Data: map[string]interface{}{"ticket": secure.Digest(token), "mode": t.Mode}})
}
func (c *Challenge) verify(t Ticket, token string, payload altcha.Payload) bool {
	p := payload.Challenge.Parameters
	// Bound all work before passing untrusted parameters to a KDF.
	if p.Algorithm != "PBKDF2/SHA-256" || p.Cost != t.WorkFactor || p.Cost < 1000 || p.Cost > 20000 || p.KeyLength != 32 || p.ExpiresAt != t.Expires || len(p.KeyPrefix) != 32 || len(p.Salt) != 24 || len(p.Nonce) != 24 || p.MemoryCost != 0 || p.Parallelism != 0 || p.Data["ticket"] != secure.Digest(token) || p.Data["mode"] != t.Mode || payload.Solution.Counter < 0 || payload.Solution.Counter >= 10000 || len(payload.Solution.DerivedKey) != 64 {
		return false
	}
	result, err := altcha.VerifySolution(altcha.VerifySolutionOptions{Challenge: payload.Challenge, Solution: payload.Solution, DeriveKey: altcha.DeriveKeyPBKDF2(), HMACSignatureSecret: secure.Sign(c.key, "altcha", token)})
	return err == nil && result.Verified
}
func (c *Challenge) consumed(t Ticket) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	return c.used[t.Nonce] > c.now().Unix() || len(c.used) >= c.capacity
}
func (c *Challenge) consume(t Ticket) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	if t.Expires <= c.now().Unix() || c.used[t.Nonce] > c.now().Unix() || len(c.used) >= c.capacity {
		return false
	}
	c.used[t.Nonce] = t.Expires
	return true
}
func (c *Challenge) Serve(w http.ResponseWriter, r *http.Request, site, ip string, revision int64) ChallengeResult {
	result := ChallengeResult{Action: "challenge_service"}
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil && !c.development {
		challengeError(w, 403, "https_required")
		return result
	}
	if strings.HasPrefix(r.URL.Path, ChallengePath+"/assets/") {
		if web.ServeChallengeAsset(w, r) {
			result.Action = "challenge_asset"
		}
		return result
	}
	if !c.limits.Allow("service:"+ip, 3, 20, 0) {
		w.Header().Set("Retry-After", "1")
		challengeError(w, 429, "challenge_rate_limited")
		return result
	}
	var token, payload string
	switch {
	case r.Method == "GET" && (r.URL.Path == ChallengePath || r.URL.Path == ChallengePath+"/puzzle"):
		token = r.URL.Query().Get("ticket")
	case r.Method == "POST" && r.URL.Path == ChallengePath+"/solve":
		if origin := r.Header.Get("Origin"); origin != "" && origin != scheme(r)+"://"+r.Host {
			challengeError(w, 403, "invalid_origin")
			return result
		}
		var body struct {
			Ticket  string `json:"ticket"`
			Payload string `json:"payload"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		d.DisallowUnknownFields()
		if err := d.Decode(&body); err != nil {
			challengeError(w, 400, "invalid_request")
			return result
		}
		if err := d.Decode(new(any)); err != io.EOF {
			challengeError(w, 400, "invalid_request")
			return result
		}
		token, payload = body.Ticket, body.Payload
	default:
		challengeError(w, 404, "not_found")
		return result
	}
	t, err := c.decode(token, "puzzle")
	if err != nil || t.Epoch != c.epoch || !c.bound(t, r, site, ip, revision) || !config.IsChallengeAction(t.Action) || (t.Mode != Interactive && t.Mode != NonInteractive) {
		challengeError(w, 403, "invalid_or_expired_challenge")
		return result
	}
	result = ChallengeResult{Action: t.Action, RuleID: t.Scope, Mode: t.Mode}
	if c.consumed(t) {
		challengeError(w, 403, "challenge_replayed_or_capacity_reached")
		return result
	}
	if r.Method == "GET" {
		if r.URL.Path == ChallengePath {
			c.Page(w, r, token, 200)
			return result
		}
		puzzle, err := c.puzzle(t, token)
		if err != nil {
			challengeError(w, 503, "challenge_unavailable")
			return result
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(puzzle)
		return result
	}
	var proof altcha.Payload
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(raw, &proof) != nil || !c.verify(t, token, proof) {
		c.failed(t, ip)
		challengeError(w, 403, "invalid_proof")
		return result
	}
	if !c.consume(t) {
		challengeError(w, 403, "challenge_replayed_or_capacity_reached")
		return result
	}
	now := c.now().Unix()
	expiry := now + int64(t.Clearance)
	clearance := Ticket{Site: t.Site, Revision: t.Revision, Host: t.Host, Binding: t.Binding, Expires: expiry, Scopes: []ClearanceScope{{Scope: t.Scope, Expires: expiry}}}
	if previous, err := r.Cookie(c.cookieName()); err == nil {
		if old, err := c.decode(previous.Value, "clearance"); err == nil && c.bound(old, r, site, ip, revision) {
			for _, grant := range old.Scopes {
				if grant.Scope != t.Scope && grant.Expires > now && len(clearance.Scopes) < 16 {
					clearance.Scopes = append(clearance.Scopes, grant)
					clearance.Expires = max(clearance.Expires, grant.Expires)
				}
			}
		}
	}
	value := c.encode(clearance, "clearance")
	if len(value) > 3800 {
		challengeError(w, 403, "clearance_capacity_reached")
		return result
	}
	c.mu.Lock()
	delete(c.failures, riskKey(site, t.Scope, ip, revision))
	c.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: c.cookieName(), Value: value, Path: "/", HttpOnly: true, Secure: !c.development, SameSite: http.SameSiteLaxMode, MaxAge: int(clearance.Expires - now)})
	response := map[string]any{"cleared": true}
	if t.Navigate && validReturn(t.Return) {
		response["redirect"] = t.Return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	return result
}
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
