package policy

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"waf/internal/config"
)

const CRSVersion = "4.25.0"

type ManagedRule struct {
	ID       int      `json:"id"`
	Group    string   `json:"group"`
	Message  string   `json:"message"`
	Tags     []string `json:"tags"`
	Paranoia int      `json:"paranoia"`
	Tunable  bool     `json:"tunable"`
}

var catalogOnce sync.Once
var catalog []ManagedRule
var catalogIDs map[int]bool

func Catalog() []ManagedRule {
	catalogOnce.Do(func() {
		catalogIDs = map[int]bool{}
		idRE := regexp.MustCompile(`\bid:([0-9]+)`)
		msgRE := regexp.MustCompile(`msg:'([^']*)'`)
		tagRE := regexp.MustCompile(`tag:'([^']*)'`)
		fs.WalkDir(crs.FS, "@owasp_crs", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".conf") {
				return nil
			}
			b, e := fs.ReadFile(crs.FS, path)
			if e != nil {
				return e
			}
			text := string(b)
			indices := idRE.FindAllStringSubmatchIndex(text, -1)
			for i, m := range indices {
				id, _ := strconv.Atoi(text[m[2]:m[3]])
				if catalogIDs[id] {
					continue
				}
				end := len(text)
				if i+1 < len(indices) {
					end = indices[i+1][0]
				}
				chunk := text[m[0]:end]
				r := ManagedRule{ID: id, Group: strings.TrimSuffix(filepath.Base(path), ".conf"), Tags: []string{}, Paranoia: 1, Tunable: Tunable(id)}
				if msg := msgRE.FindStringSubmatch(chunk); len(msg) > 1 {
					r.Message = msg[1]
				}
				for _, tag := range tagRE.FindAllStringSubmatch(chunk, -1) {
					r.Tags = append(r.Tags, tag[1])
					if strings.HasPrefix(tag[1], "paranoia-level/") {
						r.Paranoia, _ = strconv.Atoi(strings.TrimPrefix(tag[1], "paranoia-level/"))
					}
				}
				catalog = append(catalog, r)
				catalogIDs[id] = true
			}
			return nil
		})
		sort.Slice(catalog, func(i, j int) bool { return catalog[i].ID < catalog[j].ID })
	})
	return catalog
}

// Initialization, score evaluation and reporting rules are not detector exceptions.
func Tunable(id int) bool { return id >= 910000 && id < 949000 || id >= 950000 && id < 959000 }
func Description(id int) string {
	for _, rule := range Catalog() {
		if rule.ID == id {
			return rule.Message
		}
	}
	return "Managed rule matched"
}

type CompiledRule struct {
	Config     config.CustomRule
	Expression *Expression
}
type CompiledRate struct {
	Config     config.RateLimitPolicy
	Expression *Expression
}
type Site struct {
	Config  config.Site
	Rules   []CompiledRule
	Rates   []CompiledRate
	Managed map[string]coraza.WAF
}
type Compiled struct {
	Sites []*Site
	wafs  []coraza.WAF
}

func Profile(r config.RoutePolicy) string { return fmt.Sprintf("%s:%d", r.BodyMode, r.MaxBodyBytes) }
func (c *Compiled) Close() {
	for _, w := range c.wafs {
		if closer, ok := w.(experimental.WAFCloser); ok {
			closer.Close()
		}
	}
}
func Compile(bundle config.Bundle, boot config.Bootstrap) (out *Compiled, err error) {
	out = &Compiled{}
	defer func() {
		if err != nil {
			out.Close()
		}
	}()
	Catalog()
	shared := map[string]coraza.WAF{}
	for _, cfg := range bundle.Sites {
		s := &Site{Config: cfg, Managed: map[string]coraza.WAF{}}
		for _, rule := range cfg.Rules {
			p, e := CompileExpression(rule.Expression)
			if e != nil {
				return out, fmt.Errorf("site %s rule %s: %w", cfg.ID, rule.ID, e)
			}
			s.Rules = append(s.Rules, CompiledRule{Config: rule, Expression: p})
		}
		for _, rate := range cfg.RateLimits {
			p, e := CompileExpression(rate.Expression)
			if e != nil {
				return out, fmt.Errorf("site %s rate %s: %w", cfg.ID, rate.ID, e)
			}
			s.Rates = append(s.Rates, CompiledRate{Config: rate, Expression: p})
		}
		for _, x := range cfg.Managed.Exclusions {
			if !catalogIDs[x.RuleID] {
				return out, fmt.Errorf("unknown CRS %s rule id %d", CRSVersion, x.RuleID)
			}
			if !Tunable(x.RuleID) {
				return out, fmt.Errorf("CRS control rule %d cannot be excluded; change the managed policy mode instead", x.RuleID)
			}
		}
		if cfg.Managed.Mode != "off" {
			routes := append([]config.RoutePolicy{config.DefaultRoute()}, cfg.Routes...)
			for _, route := range routes {
				profile := Profile(route)
				if _, ok := s.Managed[profile]; ok {
					continue
				}
				directives := managedDirectives(cfg.Managed, route, filepath.Join(boot.DataDir, "tmp"))
				w, ok := shared[directives]
				if !ok {
					if len(shared) >= 128 {
						return out, fmt.Errorf("configuration exceeds 128 distinct managed inspection profiles")
					}
					w, err = coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithDirectives(directives))
					if err != nil {
						return out, fmt.Errorf("site %s managed rules: %w", cfg.ID, err)
					}
					shared[directives] = w
					out.wafs = append(out.wafs, w)
				}
				s.Managed[profile] = w
			}
		}
		out.Sites = append(out.Sites, s)
	}
	return out, nil
}
func managedDirectives(m config.ManagedPolicy, r config.RoutePolicy, tmp string) string {
	mode := "DetectionOnly"
	if m.Mode == "block" {
		mode = "On"
	}
	body := "On"
	if r.BodyMode == "stream" {
		body = "Off"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Include @coraza.conf-recommended\nSecRuleEngine %s\nSecAuditEngine Off\nSecDebugLogLevel 0\nSecRequestBodyAccess %s\nSecResponseBodyAccess Off\nSecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\nSecRequestBodyInMemoryLimit %d\nSecRequestBodyLimitAction Reject\nSecTmpDir %q\n", mode, body, r.MaxBodyBytes, r.MaxBodyBytes, min(int64(131072), r.MaxBodyBytes), tmp)
	fmt.Fprintf(&b, "SecUploadDir %q\nSecUploadKeepFiles Off\nSecRequestBodyJsonDepthLimit 128\nSecArgumentsLimit 1000\n", tmp)
	fmt.Fprintf(&b, "SecAction \"id:100001,phase:1,pass,nolog,setvar:tx.paranoia_level=%d,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", m.Paranoia, m.Paranoia, m.Paranoia, m.Threshold)
	if r.BodyMode == "stream" {
		b.WriteString("SecAction \"id:100002,phase:1,pass,nolog,setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/octet-stream|'\"\n")
	}
	for i, x := range m.Exclusions {
		if x.PathPrefix == "" {
			continue
		}
		action := fmt.Sprintf("ctl:ruleRemoveById=%d", x.RuleID)
		if x.Target != "" {
			action = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", x.RuleID, x.Target)
		}
		fmt.Fprintf(&b, "SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,nolog,%s\"\n", x.PathPrefix, 110000+i, action)
	}
	b.WriteString("Include @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n")
	for _, x := range m.Exclusions {
		if x.PathPrefix != "" {
			continue
		}
		if x.Target == "" {
			fmt.Fprintf(&b, "SecRuleRemoveById %d\n", x.RuleID)
		} else {
			fmt.Fprintf(&b, "SecRuleUpdateTargetById %d \"!%s\"\n", x.RuleID, x.Target)
		}
	}
	return b.String()
}
