package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Scope explicitly distinguishes all sites from a nonempty selection.
type Scope struct {
	Mode    string   `json:"mode"`
	SiteIDs []string `json:"site_ids"`
}

func (s *Scope) NormalizeAndValidate(sites map[string]bool) error {
	if s.Mode == "" && len(s.SiteIDs) == 0 {
		s.Mode = "all"
	}
	if s.Mode == "all" {
		if len(s.SiteIDs) != 0 {
			return errors.New("all-sites scope cannot contain site_ids")
		}
		return nil
	}
	if s.Mode != "sites" || len(s.SiteIDs) == 0 || len(s.SiteIDs) > 200 {
		return errors.New("scope requires all or a nonempty selection of sites")
	}
	seen := map[string]bool{}
	for _, id := range s.SiteIDs {
		if !ValidID(id) || seen[id] {
			return fmt.Errorf("invalid or duplicate scope site %q", id)
		}
		if sites != nil && !sites[id] {
			return fmt.Errorf("scope references unknown site %q; update its rules before removing the site", id)
		}
		seen[id] = true
	}
	return nil
}
func (s Scope) Matches(siteID string) bool {
	if s.Mode == "all" || s.Mode == "" && len(s.SiteIDs) == 0 {
		return true
	}
	if s.Mode == "sites" {
		for _, id := range s.SiteIDs {
			if id == siteID {
				return true
			}
		}
	}
	return false
}

type Security struct {
	CustomRules []CustomRule      `json:"custom_rules"`
	RateLimits  []RateLimitPolicy `json:"rate_limits"`
	Managed     ManagedSecurity   `json:"managed"`
}
type ManagedSecurity struct {
	Default   ManagedPolicy     `json:"default"`
	Overrides []ManagedOverride `json:"overrides"`
}
type ManagedOverride struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Enabled    bool          `json:"enabled"`
	Priority   int           `json:"priority"`
	Scope      Scope         `json:"scope"`
	Expression string        `json:"expression"`
	Policy     ManagedPolicy `json:"policy"`
}

func DefaultManaged() ManagedPolicy {
	return ManagedPolicy{Mode: "observe", Paranoia: 1, Threshold: 5, Exclusions: []Exclusion{}}
}
func DefaultSecurity() Security {
	return Security{CustomRules: []CustomRule{}, RateLimits: []RateLimitPolicy{}, Managed: ManagedSecurity{Default: DefaultManaged(), Overrides: []ManagedOverride{}}}
}
func DefaultBundle() Bundle { return Bundle{Sites: []Site{}, Security: DefaultSecurity()} }

var ErrUnsupportedConfiguration = errors.New("unsupported configuration (site-level security is no longer supported)")

// Persisted drafts and revisions get the same strict decoding as API requests.
func (b *Bundle) UnmarshalJSON(raw []byte) error {
	type bundleData Bundle
	var next bundleData
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&next); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedConfiguration, err)
	}
	*b = Bundle(next)
	return nil
}
func (s *Security) NormalizeAndValidate(sites map[string]bool) error {
	if len(s.CustomRules) > 2000 || len(s.RateLimits) > 1000 || len(s.Managed.Overrides) > 200 {
		return errors.New("configuration exceeds global policy count limits")
	}
	rids := map[string]bool{}
	for j := range s.CustomRules {
		r := &s.CustomRules[j]
		if err := r.Scope.NormalizeAndValidate(sites); err != nil {
			return fmt.Errorf("custom rule %s: %w", r.ID, err)
		}
		if IsChallengeAction(r.Action) {
			if r.Challenge == nil {
				options := DefaultChallenge()
				r.Challenge = &options
			}
			if r.Challenge.WorkFactor < 1000 || r.Challenge.WorkFactor > 20000 || r.Challenge.ClearanceSeconds < 60 || r.Challenge.ClearanceSeconds > 86400 {
				return errors.New("invalid challenge options")
			}
		} else if r.Challenge != nil {
			return errors.New("challenge options require a challenge action")
		}
		if !ValidID(r.ID) || rids[r.ID] || len(r.Name) > 128 || len(r.Expression) > 4096 {
			return errors.New("invalid custom rule")
		}
		rids[r.ID] = true
		if r.Action != "block" && r.Action != "log" && !IsChallengeAction(r.Action) && r.Action != "skip" {
			return errors.New("invalid rule action")
		}
		if r.Action == "skip" && len(r.Skip) == 0 {
			return errors.New("skip requires explicit targets")
		}
	}
	rateIDs := map[string]bool{}
	for i := range s.RateLimits {
		r := &s.RateLimits[i]
		if err := r.Scope.NormalizeAndValidate(sites); err != nil {
			return fmt.Errorf("rate rule %s: %w", r.ID, err)
		}
		if !ValidID(r.ID) || rateIDs[r.ID] || r.RequestsPerSecond <= 0 || r.RequestsPerSecond > 100000 || r.Burst < 1 || r.Burst > 100000 || r.BanSeconds < 0 || r.BanSeconds > 86400 || len(r.Expression) > 4096 {
			return errors.New("invalid rate limit")
		}
		rateIDs[r.ID] = true
		if r.Key != "ip" && r.Key != "site" && r.Key != "ip_path" {
			return errors.New("invalid rate key")
		}
	}
	for _, r := range s.CustomRules {
		for _, k := range r.Skip {
			if k != "managed" && k != "custom_rules" && k != "rate_limits" && !strings.HasPrefix(k, "rate:") && !strings.HasPrefix(k, "rule:") {
				return errors.New("invalid skip target")
			}
			if strings.HasPrefix(k, "rate:") && !rateIDs[strings.TrimPrefix(k, "rate:")] {
				return errors.New("unknown skipped rate policy")
			}
			if strings.HasPrefix(k, "rule:") && !rids[strings.TrimPrefix(k, "rule:")] {
				return errors.New("unknown skipped rule")
			}
		}
	}

	sort.SliceStable(s.CustomRules, func(i, j int) bool { return s.CustomRules[i].Priority < s.CustomRules[j].Priority })
	if err := s.Managed.Default.normalizeAndValidate(sites); err != nil {
		return fmt.Errorf("default managed policy: %w", err)
	}
	ids := map[string]bool{"default": true}
	for i := range s.Managed.Overrides {
		o := &s.Managed.Overrides[i]
		if !ValidID(o.ID) || ids[o.ID] || len(o.Name) > 128 || len(o.Expression) > 4096 {
			return errors.New("invalid or duplicate managed override (default is reserved)")
		}
		ids[o.ID] = true
		if err := o.Scope.NormalizeAndValidate(sites); err != nil {
			return fmt.Errorf("managed override %s: %w", o.ID, err)
		}
		if err := o.Policy.normalizeAndValidate(sites); err != nil {
			return fmt.Errorf("managed override %s: %w", o.ID, err)
		}
	}
	sort.SliceStable(s.Managed.Overrides, func(i, j int) bool { return s.Managed.Overrides[i].Priority < s.Managed.Overrides[j].Priority })
	// Also bound all-site rules before the first site has been created.
	candidates := []string{""}
	for id := range sites {
		candidates = append(candidates, id)
	}
	for _, id := range candidates {
		rules, rates, challenges := 0, 0, 0
		for _, r := range s.CustomRules {
			if r.Scope.Matches(id) {
				rules++
				if IsChallengeAction(r.Action) {
					challenges++
				}
			}
		}
		for _, r := range s.RateLimits {
			if r.Scope.Matches(id) {
				rates++
			}
		}
		if rules > 200 || rates > 100 || challenges > 16 {
			return fmt.Errorf("site %q exceeds 200 custom rules, 100 rate rules or 16 challenge rules", id)
		}
	}
	return nil
}
func (m *ManagedPolicy) normalizeAndValidate(sites map[string]bool) error {
	if m.Mode == "" {
		m.Mode = "observe"
	}
	if m.Paranoia == 0 {
		m.Paranoia = 1
	}
	if m.Threshold == 0 {
		m.Threshold = 5
	}
	if m.Mode != "off" && m.Mode != "observe" && m.Mode != "block" {
		return errors.New("managed mode must be off, observe or block")
	}
	if m.Paranoia < 1 || m.Paranoia > 4 || m.Threshold < 1 || m.Threshold > 100 {
		return errors.New("invalid managed policy")
	}
	if len(m.Exclusions) > 500 {
		return errors.New("too many exclusions")
	}
	for i := range m.Exclusions {
		x := &m.Exclusions[i]
		if err := x.Scope.NormalizeAndValidate(sites); err != nil {
			return fmt.Errorf("exclusion %d: %w", x.RuleID, err)
		}
		if x.RuleID < 900000 || x.RuleID > 999999 || strings.ContainsAny(x.PathPrefix, "\r\n\"\\") || x.PathPrefix != "" && !strings.HasPrefix(x.PathPrefix, "/") || x.Target != "" && !targetPattern.MatchString(x.Target) {
			return errors.New("invalid managed rule exclusion")
		}
	}

	return nil
}
