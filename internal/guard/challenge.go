package guard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"waf/internal/secure"
)

const ChallengePath = "/.waf/challenge"

type Ticket struct {
	Nonce      string   `json:"nonce"`
	Site       string   `json:"site"`
	Scope      string   `json:"scope"`
	Scopes     []string `json:"scopes,omitempty"`
	Revision   int64    `json:"revision"`
	Host       string   `json:"host"`
	Binding    string   `json:"binding"`
	Expires    int64    `json:"expires"`
	Difficulty int      `json:"difficulty"`
	Clearance  int      `json:"clearance"`
	Return     string   `json:"return"`
	Epoch      string   `json:"epoch"`
}
type Challenge struct {
	key         []byte
	epoch       string
	mu          sync.Mutex
	used        map[string]int64
	limits      *Limits
	development bool
}

func NewChallenge(key []byte, development bool) *Challenge {
	return &Challenge{key: key, epoch: secure.Random(16), used: map[string]int64{}, limits: NewLimits(10000), development: development}
}
func binding(ip, ua string) string { return secure.Digest(ip + "\x00" + ua) }
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
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return t, e
	}
	e = json.Unmarshal(b, &t)
	if e != nil || t.Expires <= time.Now().Unix() {
		return t, errors.New("expired token")
	}
	return t, nil
}
func (c *Challenge) Cleared(r *http.Request, site, scope, ip string, revision int64) bool {
	cookie, e := r.Cookie("__Host-waf_clearance")
	if c.development && e != nil {
		cookie, e = r.Cookie("waf_clearance_dev")
	}
	if e != nil {
		return false
	}
	t, e := c.decode(cookie.Value, "clearance")
	if e != nil || t.Site != site || t.Revision != revision || t.Host != r.Host || !secure.Equal(t.Binding, binding(ip, r.UserAgent())) {
		return false
	}
	for _, cleared := range t.Scopes {
		if cleared == scope {
			return true
		}
	}
	return false
}
func (c *Challenge) Issue(r *http.Request, site, scope, ip string, revision int64, difficulty, clearance int) string {
	target := r.URL.RequestURI()
	if !validReturn(target) {
		target = "/"
	}
	t := Ticket{Nonce: secure.Random(24), Site: site, Scope: scope, Revision: revision, Host: r.Host, Binding: binding(ip, r.UserAgent()), Expires: time.Now().Add(2 * time.Minute).Unix(), Difficulty: difficulty, Clearance: clearance, Return: target, Epoch: c.epoch}
	return c.encode(t, "puzzle")
}
func validReturn(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n") {
		return false
	}
	u, e := url.ParseRequestURI(s)
	return e == nil && u.Host == "" && !u.IsAbs()
}
func (c *Challenge) Deny(w http.ResponseWriter, r *http.Request, site, scope, ip string, revision int64, difficulty, clearance int, interactive bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !c.limits.Allow("issue:"+ip, 3, 20, 0) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "challenge issuance rate limited", 429)
		return
	}
	if r.TLS == nil && !c.development {
		http.Error(w, "HTTPS is required for a browser challenge", 403)
		return
	}
	token := c.Issue(r, site, scope, ip, revision, difficulty, clearance)
	if interactive && r.Method == "GET" && strings.Contains(r.Header.Get("Accept"), "text/html") && !strings.Contains(r.Header.Get("Accept"), "text/event-stream") && !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		c.Page(w, r, token, 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	json.NewEncoder(w).Encode(map[string]string{"error": "challenge_required", "challenge_url": ChallengePath + "?ticket=" + url.QueryEscape(token)})
}

var challengeTemplate = template.Must(template.New("challenge").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>浏览器安全验证</title></head><body><main><h1>正在验证浏览器</h1><p id="status">请稍候，浏览器正在完成安全验证。</p><noscript>此页面需要 JavaScript。请联系网站管理员获取其他访问方式。</noscript></main><script nonce="{{.Nonce}}">
const token={{.Token}}, difficulty={{.Difficulty}};
const worker = new Worker(URL.createObjectURL(new Blob([
"onmessage=async(e)=>{const {token,difficulty}=e.data;const encoder=new TextEncoder();for(let n=0;n<16777216;n++){const h=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(token+':'+n)));let bits=difficulty,ok=true;for(const b of h){if(bits<=0)break;const k=Math.min(8,bits);if((b >>> (8-k))!==0){ok=false;break;}bits-=k;}if(ok){postMessage({answer:String(n)});return;}}postMessage({error:'验证计算已达到上限，请刷新重试。'});};"
],{type:'text/javascript'})));
const status=document.getElementById('status');
worker.onmessage=async(e)=>{worker.terminate();if(e.data.error){status.textContent=e.data.error;return;}try{const response=await fetch('/.waf/challenge/solve',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({ticket:token,answer:e.data.answer})});const result=await response.json();if(!response.ok)throw new Error(result.error||'验证失败');status.textContent='验证成功';location.replace(result.redirect);}catch(err){status.textContent='验证失败或已过期，请返回原页面重试。';}};
worker.onerror=()=>{status.textContent='浏览器无法完成验证，请联系网站管理员。';worker.terminate();};worker.postMessage({token,difficulty});
</script></body></html>`))

func (c *Challenge) Page(w http.ResponseWriter, r *http.Request, token string, status int) {
	t, e := c.decode(token, "puzzle")
	if e != nil || t.Epoch != c.epoch {
		http.Error(w, "expired challenge", 403)
		return
	}
	nonce := secure.Random(18)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; worker-src blob:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	challengeTemplate.Execute(w, map[string]any{"Nonce": nonce, "Token": token, "Difficulty": t.Difficulty})
}
func (c *Challenge) Serve(w http.ResponseWriter, r *http.Request, site, ip string, revision int64) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.TLS == nil && !c.development {
		http.Error(w, "HTTPS required", 403)
		return
	}
	if !c.limits.Allow(ip, 1, 10, 0) {
		http.Error(w, "rate limited", 429)
		return
	}
	var token, answer string
	if r.Method == "GET" && r.URL.Path == ChallengePath {
		token = r.URL.Query().Get("ticket")
	} else if r.Method == "POST" && r.URL.Path == ChallengePath+"/solve" {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != scheme(r)+"://"+r.Host {
			http.Error(w, "invalid origin", 403)
			return
		}
		var body struct {
			Ticket string `json:"ticket"`
			Answer string `json:"answer"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 20480))
		d.DisallowUnknownFields()
		if e := d.Decode(&body); e != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		if e := d.Decode(new(any)); e != io.EOF {
			http.Error(w, "invalid request", 400)
			return
		}
		token, answer = body.Ticket, body.Answer
	} else {
		http.Error(w, "not found", 404)
		return
	}
	t, e := c.decode(token, "puzzle")
	if e != nil || t.Epoch != c.epoch || t.Site != site || t.Revision != revision || t.Host != r.Host || !secure.Equal(t.Binding, binding(ip, r.UserAgent())) {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_or_expired_challenge"})
		return
	}
	if r.Method == "GET" {
		c.Page(w, r, token, 200)
		return
	}
	if !ValidProof(token, answer, t.Difficulty) {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_proof"})
		return
	}
	c.mu.Lock()
	for n, exp := range c.used {
		if exp <= time.Now().Unix() {
			delete(c.used, n)
		}
	}
	_, used := c.used[t.Nonce]
	if used || len(c.used) >= 10000 {
		c.mu.Unlock()
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]string{"error": "challenge_replayed_or_capacity_reached"})
		return
	}
	c.used[t.Nonce] = t.Expires
	c.mu.Unlock()
	t.Expires = time.Now().Add(time.Duration(t.Clearance) * time.Second).Unix()
	t.Scopes = []string{t.Scope}
	t.Nonce = ""
	name := "__Host-waf_clearance"
	if c.development {
		name = "waf_clearance_dev"
	}
	if previous, err := r.Cookie(name); err == nil {
		if old, err := c.decode(previous.Value, "clearance"); err == nil && old.Site == t.Site && old.Revision == t.Revision && old.Host == t.Host && secure.Equal(old.Binding, t.Binding) {
			for _, scope := range old.Scopes {
				if scope != t.Scope && len(t.Scopes) < 32 {
					t.Scopes = append(t.Scopes, scope)
				}
			}
		}
	}
	target := t.Return
	if !validReturn(target) {
		target = "/"
	}
	maxAge := t.Clearance
	// Keep URL parameters out of the clearance credential, and below cookie size limits.
	t.Return, t.Scope, t.Epoch = "", "", ""
	t.Clearance, t.Difficulty = 0, 0
	http.SetCookie(w, &http.Cookie{Name: name, Value: c.encode(t, "clearance"), Path: "/", HttpOnly: true, Secure: !c.development, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	json.NewEncoder(w).Encode(map[string]string{"redirect": target})
}
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
func ValidProof(token, answer string, difficulty int) bool {
	if difficulty < 8 || difficulty > 22 || len(answer) < 1 || len(answer) > 8 {
		return false
	}
	n, e := strconv.ParseUint(answer, 10, 32)
	if e != nil || strconv.FormatUint(n, 10) != answer || n >= 1<<24 {
		return false
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", token, answer)))
	for _, b := range sum {
		if difficulty <= 0 {
			return true
		}
		k := min(8, difficulty)
		if b>>(8-k) != 0 {
			return false
		}
		difficulty -= k
	}
	return difficulty <= 0
}
