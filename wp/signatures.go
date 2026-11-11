package wp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"ghostpress/data"
	"ghostpress/httpclient"
	"ghostpress/model"
)

// Signatures are data-driven WAF fingerprints and misconfiguration checks loaded
// from signatures.json (embedded default, overridable at ~/.ghostpress/signatures.json
// or via --signatures, refreshable with `ghostpress update`). The matcher
// vocabulary below is deliberately fixed and small - status/word/regex/header/
// cookie, plus a couple of named primitives - so this is a signature format, not
// a general template engine.

type signatureSet struct {
	Meta      map[string]string `json:"_meta"`
	WAF       []wafSignature    `json:"waf"`
	Misconfig []misconfigCheck  `json:"misconfig"`
}

type wafSignature struct {
	Vendor     string       `json:"vendor"`
	Confidence int          `json:"confidence"`
	Condition  string       `json:"condition"` // "and" | "or" (default "or")
	Matchers   []sigMatcher `json:"matchers"`
}

type sigMatcher struct {
	Where    string `json:"where"` // header | cookie | body
	Name     string `json:"name"`  // header name, when where=header
	Contains string `json:"contains"`
	Regex    string `json:"regex"`
	Negative bool   `json:"negative"`

	re *regexp.Regexp // compiled Regex
}

type misconfigCheck struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Severity  string       `json:"severity"`
	Mode      string       `json:"mode"`   // minimum detection mode: passive|mixed|aggressive
	Source    string       `json:"source"` // "homepage" => match the already-fetched homepage response
	Reference string       `json:"reference"`
	Match     *sigMatch    `json:"match"` // used when source=homepage
	Requests  []sigRequest `json:"requests"`
}

type sigRequest struct {
	Method  string            `json:"method"` // only GET is issued; empty == GET
	Paths   []string          `json:"paths"`
	Headers map[string]string `json:"headers"`
	Match   sigMatch          `json:"match"`
}

type sigMatch struct {
	Status         []int             `json:"status"`
	BodyContains   []string          `json:"bodyContains"`
	BodyCondition  string            `json:"bodyCondition"` // "and" (default) | "or"
	BodyRegex      string            `json:"bodyRegex"`
	HeaderContains map[string]string `json:"headerContains"`
	HeaderMissing  []string          `json:"headerMissing"`
	HeaderReflect  *headerReflect    `json:"headerReflect"`
	InsecureCookie *cookieFlagMatch  `json:"insecureCookie"`
	ContentType    string            `json:"contentType"`
	NotContentType string            `json:"notContentType"`

	bodyRe *regexp.Regexp // compiled BodyRegex
}

type headerReflect struct {
	Name string `json:"name"` // response header, e.g. Access-Control-Allow-Origin
	Of   string `json:"of"`   // request header whose value must be echoed back, e.g. Origin
}

type cookieFlagMatch struct {
	NameContains string   `json:"nameContains"` // "" = any cookie
	Require      []string `json:"require"`      // flags that should be present, e.g. HttpOnly
}

const misconfigBodyCap = 256 * 1024

var (
	sigOnce   sync.Once
	sigParsed *signatureSet
)

// signatures returns the parsed, cached signature set. A malformed file yields an
// empty set (checks simply don't run) with a warning, so a bad override never
// breaks a scan.
func signatures() *signatureSet {
	sigOnce.Do(func() {
		sigParsed = parseSignatures(data.Signatures())
	})
	return sigParsed
}

func parseSignatures(raw []byte) *signatureSet {
	set := &signatureSet{}
	if err := json.Unmarshal(raw, set); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] signatures.json could not be parsed (%v); WAF/misconfig signatures disabled\n", err)
		return &signatureSet{}
	}
	// Compile regexes up front; drop any that don't compile (with a warning).
	for i := range set.WAF {
		for j := range set.WAF[i].Matchers {
			compileMatcherRe(&set.WAF[i].Matchers[j])
		}
	}
	for i := range set.Misconfig {
		if set.Misconfig[i].Match != nil {
			compileMatchRe(set.Misconfig[i].Match)
		}
		for j := range set.Misconfig[i].Requests {
			compileMatchRe(&set.Misconfig[i].Requests[j].Match)
		}
	}
	return set
}

func compileMatcherRe(m *sigMatcher) {
	if m.Regex == "" {
		return
	}
	re, err := regexp.Compile(m.Regex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] signatures: invalid regex %q: %v\n", m.Regex, err)
		return
	}
	m.re = re
}

func compileMatchRe(m *sigMatch) {
	if m.BodyRegex == "" {
		return
	}
	re, err := regexp.Compile(m.BodyRegex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] signatures: invalid bodyRegex %q: %v\n", m.BodyRegex, err)
		return
	}
	m.bodyRe = re
}

// sigResponse is the response view the matcher evaluates against - either an
// active probe's response or the already-captured homepage response.
type sigResponse struct {
	status      int
	headers     http.Header
	body        []byte
	sentHeaders map[string]string // request headers we sent (for headerReflect)
}

func homepageResponse(t *Target) sigResponse {
	return sigResponse{headers: t.HomepageHeaders, body: t.Homepage}
}

func respFrom(resp *httpclient.Response, sent map[string]string) sigResponse {
	return sigResponse{status: resp.StatusCode, headers: resp.Headers, body: resp.Body, sentHeaders: sent}
}

// DetectWAF fingerprints a WAF/CDN purely from the homepage response (headers,
// cookies, body) - no extra requests. Highest-confidence detection per vendor.
func DetectWAF(t *Target) []model.WAFDetection {
	set := signatures()
	r := homepageResponse(t)
	var out []model.WAFDetection
	seen := map[string]bool{}
	for _, sig := range set.WAF {
		if seen[sig.Vendor] {
			continue
		}
		if ok, ev := matchWAF(sig, r); ok {
			seen[sig.Vendor] = true
			out = append(out, model.WAFDetection{Vendor: sig.Vendor, Confidence: sig.Confidence, Evidence: ev})
		}
	}
	return out
}

func matchWAF(sig wafSignature, r sigResponse) (bool, string) {
	and := strings.EqualFold(sig.Condition, "and")
	var firstEv string
	hits := 0
	for _, m := range sig.Matchers {
		ok, ev := evalMatcher(m, r)
		if ok {
			hits++
			if firstEv == "" {
				firstEv = ev
			}
			if !and {
				return true, ev // "or": first hit wins
			}
		} else if and {
			return false, "" // "and": every matcher must hit
		}
	}
	if and {
		return hits > 0, firstEv
	}
	return false, ""
}

func evalMatcher(m sigMatcher, r sigResponse) (bool, string) {
	hit, ev := false, ""
	switch strings.ToLower(m.Where) {
	case "header":
		val := r.headers.Get(m.Name)
		switch {
		case m.Contains != "":
			hit = containsFold(val, m.Contains)
			ev = m.Name + ": " + val
		case m.re != nil:
			hit = val != "" && m.re.MatchString(val)
			ev = m.Name + " header"
		default:
			hit = val != ""
			ev = m.Name + " header"
		}
	case "cookie":
		for _, c := range r.headers.Values("Set-Cookie") {
			if (m.Contains != "" && containsFold(c, m.Contains)) || (m.re != nil && m.re.MatchString(c)) {
				hit = true
				ev = "cookie " + cookieName(c)
				break
			}
		}
	case "body":
		body := string(r.body)
		if m.Contains != "" {
			hit = strings.Contains(body, m.Contains)
		} else if m.re != nil {
			hit = m.re.MatchString(body)
		}
		ev = "response body"
	}
	if m.Negative {
		hit = !hit
	}
	return hit, ev
}

// RunMisconfigChecks runs the data-driven misconfiguration checks gated by the
// scan's detection mode, returning findings for the Interesting Findings section.
func RunMisconfigChecks(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode) []model.InterestingFinding {
	set := signatures()
	var findings []model.InterestingFinding

	for _, c := range set.Misconfig {
		if !modeAllows(mode, c.Mode) {
			continue
		}

		// Passive: match the homepage response we already have.
		if c.Source == "homepage" || len(c.Requests) == 0 {
			if c.Match == nil {
				continue
			}
			if ok, ev := matchSigMatch(*c.Match, homepageResponse(target)); ok {
				findings = append(findings, makeMisconfigFinding(c, target.EffectiveURL, ev, "Passive"))
			}
			continue
		}

		// Active: probe each path, stop at the first hit for this check.
		found := false
		for _, req := range c.Requests {
			if found {
				break
			}
			if req.Method != "" && !strings.EqualFold(req.Method, "GET") {
				continue // only GET probes are issued
			}
			for _, p := range req.Paths {
				select {
				case <-ctx.Done():
					return findings
				default:
				}
				url := target.EffectiveURL + strings.TrimPrefix(p, "/")
				resp, err := client.GetWithHeaders(ctx, url, misconfigBodyCap, req.Headers)
				if err != nil || resp == nil {
					continue
				}
				if resp.StatusCode == 200 && target.IsSoft404(resp) {
					continue
				}
				if ok, ev := matchSigMatch(req.Match, respFrom(resp, req.Headers)); ok {
					findings = append(findings, makeMisconfigFinding(c, url, ev, "Active"))
					found = true
					break
				}
			}
		}
	}
	return findings
}

// matchSigMatch reports whether every specified condition in m holds for r, and
// returns human-readable evidence entries. A match with no conditions never fires.
func matchSigMatch(m sigMatch, r sigResponse) (bool, []string) {
	any := false
	var evidence []string

	if len(m.Status) > 0 {
		any = true
		if !intIn(r.status, m.Status) {
			return false, nil
		}
	}

	ct := r.headers.Get("Content-Type")
	if m.ContentType != "" {
		any = true
		if !containsFold(ct, m.ContentType) {
			return false, nil
		}
	}
	if m.NotContentType != "" {
		any = true
		if containsFold(ct, m.NotContentType) {
			return false, nil
		}
	}

	if len(m.BodyContains) > 0 {
		any = true
		body := string(r.body)
		if strings.EqualFold(m.BodyCondition, "or") {
			hit := false
			for _, w := range m.BodyContains {
				if strings.Contains(body, w) {
					hit = true
					break
				}
			}
			if !hit {
				return false, nil
			}
		} else {
			for _, w := range m.BodyContains {
				if !strings.Contains(body, w) {
					return false, nil
				}
			}
		}
	}

	if m.bodyRe != nil {
		any = true
		if !m.bodyRe.Match(r.body) {
			return false, nil
		}
	}

	for name, sub := range m.HeaderContains {
		any = true
		if !containsFold(r.headers.Get(name), sub) {
			return false, nil
		}
	}

	if m.HeaderReflect != nil {
		any = true
		got := r.headers.Get(m.HeaderReflect.Name)
		want := r.sentHeaders[m.HeaderReflect.Of]
		if got == "" || want == "" || got != want {
			return false, nil
		}
		evidence = append(evidence, m.HeaderReflect.Name+": "+got)
	}

	if len(m.HeaderMissing) > 0 {
		any = true
		var missing []string
		for _, h := range m.HeaderMissing {
			if r.headers.Get(h) == "" {
				missing = append(missing, h)
			}
		}
		if len(missing) == 0 {
			return false, nil
		}
		evidence = append(evidence, "Missing: "+strings.Join(missing, ", "))
	}

	if m.InsecureCookie != nil {
		any = true
		var insecure []string
		for _, c := range r.headers.Values("Set-Cookie") {
			name := cookieName(c)
			if m.InsecureCookie.NameContains != "" && !containsFold(name, m.InsecureCookie.NameContains) {
				continue
			}
			var missing []string
			for _, flag := range m.InsecureCookie.Require {
				if !containsFold(c, flag) {
					missing = append(missing, flag)
				}
			}
			if len(missing) > 0 {
				insecure = append(insecure, name+" (missing "+strings.Join(missing, ", ")+")")
			}
		}
		if len(insecure) == 0 {
			return false, nil
		}
		evidence = append(evidence, insecure...)
	}

	if !any {
		return false, nil
	}
	return true, evidence
}

func makeMisconfigFinding(c misconfigCheck, url string, evidence []string, kind string) model.InterestingFinding {
	desc := c.Name
	switch strings.ToLower(c.Severity) {
	case "critical":
		desc = "[CRITICAL] " + desc
	case "high":
		desc = "[HIGH] " + desc
	}
	var refs []model.Reference
	if c.Reference != "" {
		refs = []model.Reference{{Type: "url", ID: c.Reference}}
	}
	return model.InterestingFinding{
		URL:                url,
		Type:               "misconfig:" + c.ID,
		Description:        desc,
		InterestingEntries: evidence,
		References:         refs,
		Confidence:         confidenceForSeverity(c.Severity),
		FoundBy:            "Signature (" + kind + ")",
	}
}

func confidenceForSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 100
	case "high":
		return 90
	case "medium":
		return 70
	case "low":
		return 50
	default:
		return 60
	}
}

// modeAllows reports whether a check whose minimum mode is min should run under
// the scan's detection mode. Mirrors how FindInteresting gates passive/aggressive
// work: passive checks always run; "mixed" checks run in mixed+aggressive;
// "aggressive" checks run only in aggressive.
func modeAllows(scan model.DetectionMode, min string) bool {
	switch strings.ToLower(min) {
	case "", "passive":
		return true
	case "aggressive":
		return scan == model.ModeAggressive
	default: // "mixed"
		return scan != model.ModePassive
	}
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func cookieName(setCookie string) string {
	if i := strings.IndexByte(setCookie, '='); i >= 0 {
		return strings.TrimSpace(setCookie[:i])
	}
	return strings.TrimSpace(setCookie)
}

func intIn(n int, set []int) bool {
	for _, s := range set {
		if n == s {
			return true
		}
	}
	return false
}
