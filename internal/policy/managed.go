package policy

import (
	"context"
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
var detectorIDs map[int]bool

func Catalog() []ManagedRule {
	catalogOnce.Do(func() {
		catalogIDs = map[int]bool{}
		detectorIDs = map[int]bool{}
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
				r := ManagedRule{ID: id, Group: strings.TrimSuffix(filepath.Base(path), ".conf"), Tags: []string{}, Paranoia: 1}
				if msg := msgRE.FindStringSubmatch(chunk); len(msg) > 1 {
					r.Message = msg[1]
				}
				for _, tag := range tagRE.FindAllStringSubmatch(chunk, -1) {
					r.Tags = append(r.Tags, tag[1])
					if strings.HasPrefix(tag[1], "paranoia-level/") {
						r.Paranoia, _ = strconv.Atoi(strings.TrimPrefix(tag[1], "paranoia-level/"))
					}
				}
				// Phase guards and performance controls can share a detector's ID range.
				// Only actual detector rules carry a diagnostic message in the bundled CRS.
				r.Tunable = r.Message != "" && (id >= 910000 && id < 949000 || id >= 950000 && id < 959000)
				detectorIDs[id] = r.Tunable
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
func Tunable(id int) bool { Catalog(); return detectorIDs[id] }
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
type Managed struct {
	ID       string
	Config   config.ManagedPolicy
	Profiles map[string]coraza.WAF
}
type CompiledManagedOverride struct {
	Config     config.ManagedOverride
	Expression *Expression
	Managed    *Managed
}
type Site struct {
	Config           config.Site
	Rules            []CompiledRule
	Rates            []CompiledRate
	ManagedDefault   *Managed
	ManagedOverrides []CompiledManagedOverride
}

func (s *Site) SelectManaged(ctx context.Context, data map[string]any) (*Managed, error) {
	for _, o := range s.ManagedOverrides {
		if !o.Config.Enabled {
			continue
		}
		match, err := o.Expression.Eval(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("managed override %s: %w", o.Config.ID, err)
		}
		if match {
			return o.Managed, nil
		}
	}
	return s.ManagedDefault, nil
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
	var rules []CompiledRule
	var rates []CompiledRate
	var overrides []CompiledManagedOverride
	for _, rule := range bundle.Security.CustomRules {
		p, e := CompileExpression(rule.Expression)
		if e != nil {
			return out, fmt.Errorf("custom rule %s: %w", rule.ID, e)
		}
		rules = append(rules, CompiledRule{Config: rule, Expression: p})
	}
	for _, rate := range bundle.Security.RateLimits {
		p, e := CompileExpression(rate.Expression)
		if e != nil {
			return out, fmt.Errorf("rate rule %s: %w", rate.ID, e)
		}
		rates = append(rates, CompiledRate{Config: rate, Expression: p})
	}
	validateManaged := func(m config.ManagedPolicy) error {
		for _, x := range m.Exclusions {
			if !catalogIDs[x.RuleID] {
				return fmt.Errorf("unknown CRS %s rule id %d", CRSVersion, x.RuleID)
			}
			if !Tunable(x.RuleID) {
				return fmt.Errorf("CRS control rule %d cannot be excluded; change the managed policy mode instead", x.RuleID)
			}
		}
		return nil
	}
	if err = validateManaged(bundle.Security.Managed.Default); err != nil {
		return out, err
	}
	for _, o := range bundle.Security.Managed.Overrides {
		p, e := CompileExpression(o.Expression)
		if e != nil {
			return out, fmt.Errorf("managed override %s: %w", o.ID, e)
		}
		if e = validateManaged(o.Policy); e != nil {
			return out, e
		}
		overrides = append(overrides, CompiledManagedOverride{Config: o, Expression: p})
	}
	compileManaged := func(id string, m config.ManagedPolicy, site config.Site) (*Managed, error) {
		effective := m
		effective.Exclusions = nil
		for _, x := range m.Exclusions {
			if x.Scope.Matches(site.ID) {
				effective.Exclusions = append(effective.Exclusions, x)
			}
		}
		result := &Managed{ID: id, Config: effective, Profiles: map[string]coraza.WAF{}}
		if m.Mode == "off" {
			return result, nil
		}
		routes := append([]config.RoutePolicy{config.DefaultRoute()}, site.Routes...)
		for _, route := range routes {
			profile := Profile(route)
			if _, ok := result.Profiles[profile]; ok {
				continue
			}
			directives := managedDirectives(effective, route, filepath.Join(boot.DataDir, "tmp"))
			w, ok := shared[directives]
			if !ok {
				if len(shared) >= 128 {
					return nil, fmt.Errorf("configuration exceeds 128 distinct managed inspection profiles")
				}
				var e error
				w, e = coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithDirectives(directives))
				if e != nil {
					return nil, fmt.Errorf("site %s managed policy %s: %w", site.ID, id, e)
				}
				shared[directives] = w
				out.wafs = append(out.wafs, w)
			}
			result.Profiles[profile] = w
		}
		return result, nil
	}
	for _, cfg := range bundle.Sites {
		s := &Site{Config: cfg}
		for _, rule := range rules {
			if rule.Config.Scope.Matches(cfg.ID) {
				s.Rules = append(s.Rules, rule)
			}
		}
		for _, rate := range rates {
			if rate.Config.Scope.Matches(cfg.ID) {
				s.Rates = append(s.Rates, rate)
			}
		}
		s.ManagedDefault, err = compileManaged("default", bundle.Security.Managed.Default, cfg)
		if err != nil {
			return out, err
		}
		for _, o := range overrides {
			if !o.Config.Scope.Matches(cfg.ID) || !o.Config.Enabled {
				continue
			}
			o.Managed, err = compileManaged(o.Config.ID, o.Config.Policy, cfg)
			if err != nil {
				return out, err
			}
			s.ManagedOverrides = append(s.ManagedOverrides, o)
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
