package wp

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"ghostpress/data"
	"ghostpress/httpclient"
	"ghostpress/model"
)

func DetectVersion(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode) *model.WPVersion {
	var candidates []model.WPVersion

	if mode != model.ModeAggressive {
		candidates = append(candidates, passiveVersionFinders(target)...)
	}

	if mode != model.ModePassive {
		candidates = append(candidates, aggressiveVersionFinders(ctx, client, target)...)
	}

	var best *model.WPVersion
	if len(candidates) > 0 {
		b := candidates[0]
		for _, c := range candidates[1:] {
			if c.Confidence > b.Confidence {
				b = c
			}
		}
		if b.Confidence >= 40 {
			best = &b
		} else {
			debugf("version: best candidate %q conf %d below threshold 40", b.Number, b.Confidence)
		}
	}

	// Upgrade inference to cryptographic proof against api.wordpress.org. This is
	// aggressive-only and opt-out; it also corrects a stale fingerprint guess, and
	// can supply a version when offline detection found none.
	if mode == model.ModeAggressive {
		guess := ""
		if best != nil {
			guess = best.Number
		}
		if proven := confirmVersionViaChecksums(ctx, client, target, guess); proven != nil {
			debugf("version: checksum-confirmed %s (offline guess was %q)", proven.Number, guess)
			best = proven
		}
	}

	if best == nil {
		return nil
	}

	best.Vulnerabilities = lookupWPVulns(best.Number)
	if best.Number != "" {
		best.Status = "insecure"
	}

	debugf("version: %s (%s, conf %d, %d vulns)", best.Number, best.FoundBy, best.Confidence, len(best.Vulnerabilities))
	return best
}

func passiveVersionFinders(target *Target) []model.WPVersion {
	var results []model.WPVersion
	body := string(target.Homepage)

	metaRe := regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)["']`)
	if m := metaRe.FindStringSubmatch(body); len(m) > 1 {
		results = append(results, model.WPVersion{
			Number:             m[1],
			FoundBy:            "Meta Generator (Passive)",
			Confidence:         80,
			InterestingEntries: []string{m[0]},
		})
	}

	feedPatterns := []struct {
		pattern string
		name    string
	}{
		{`<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>`, "RSS Generator"},
		{`<generator uri="https?://wordpress\.org/" version="([\d.]+)"`, "Atom Generator"},
	}
	for _, fp := range feedPatterns {
		re := regexp.MustCompile(fp.pattern)
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			results = append(results, model.WPVersion{
				Number:             m[1],
				FoundBy:            fp.name + " (Passive)",
				Confidence:         80,
				InterestingEntries: []string{m[0]},
			})
		}
	}

	cssJSRe := regexp.MustCompile(`(?:wp-content|wp-includes)/[^"']+\?ver=([\d.]+)`)
	if m := cssJSRe.FindStringSubmatch(body); len(m) > 1 {
		results = append(results, model.WPVersion{
			Number:     m[1],
			FoundBy:    "Query Parameter in Assets (Passive)",
			Confidence: 30,
		})
	}

	return results
}

func aggressiveVersionFinders(ctx context.Context, client *httpclient.Client, target *Target) []model.WPVersion {
	var results []model.WPVersion

	// The most reliable core signal: wp-login.php stamps its wp-admin assets with
	// the core version. It is version-agnostic (reads whatever is served) so it
	// detects brand-new releases with no fingerprint DB and no rebuild.
	if ver := loginAssetVersion(ctx, client, target); ver != nil {
		results = append(results, *ver)
	}

	feedPaths := []struct {
		path    string
		pattern string
		name    string
	}{
		{"feed/", `<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>`, "RSS Generator"},
		{"feed/atom/", `<generator uri="https?://wordpress\.org/" version="([\d.]+)"`, "Atom Generator"},
		{"feed/rdf/", `<admin:generatorAgent rdf:resource="https?://wordpress\.org/\?v=([\d.]+)"`, "RDF Generator"},
		{"comments/feed/", `<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>`, "Comments RSS"},
	}

	for _, fp := range feedPaths {
		resp, err := client.Get(ctx, target.EffectiveURL+fp.path)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		re := regexp.MustCompile(fp.pattern)
		if m := re.FindStringSubmatch(string(resp.Body)); len(m) > 1 {
			results = append(results, model.WPVersion{
				Number:             m[1],
				FoundBy:            fp.name + " (Aggressive)",
				Confidence:         90,
				InterestingEntries: []string{target.EffectiveURL + fp.path},
			})
			break
		}
	}

	resp, err := client.Get(ctx, target.EffectiveURL+"readme.html")
	if err == nil && resp.StatusCode == 200 {
		re := regexp.MustCompile(`(?i)<br\s*/?\s*>\s*version\s+([\d.]+)`)
		if m := re.FindStringSubmatch(string(resp.Body)); len(m) > 1 {
			results = append(results, model.WPVersion{
				Number:             m[1],
				FoundBy:            "Readme (Aggressive)",
				Confidence:         90,
				InterestingEntries: []string{target.EffectiveURL + "readme.html"},
			})
		}
	}

	if ver := fingerprintVersion(ctx, client, target); ver != nil {
		results = append(results, *ver)
	}

	return results
}

// loginAssetVersion reads wp-login.php, whose wp-admin CSS/JS are stamped with
// the WordPress *core* version via ?ver=. Unlike homepage wp-content assets
// (which carry plugin/library versions such as jQuery's), these track core
// precisely and need no fingerprint database, so a freshly shipped release is
// detected without rebuilding. The modal stamp across several core assets is
// used, so a single plugin-overridden stamp cannot skew the result.
func loginAssetVersion(ctx context.Context, client *httpclient.Client, target *Target) *model.WPVersion {
	resp, err := client.Get(ctx, target.EffectiveURL+"wp-login.php")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	re := regexp.MustCompile(`wp-admin/(?:css|js)/[^"'?]+\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	matches := re.FindAllStringSubmatch(string(resp.Body), -1)
	if len(matches) == 0 {
		return nil
	}
	counts := make(map[string]int)
	for _, m := range matches {
		counts[m[1]]++
	}
	best, bestN := modalVersion(counts)
	if best == "" {
		return nil
	}
	return &model.WPVersion{
		Number:     best,
		FoundBy:    "Login Page Assets (Aggressive)",
		Confidence: 90,
		InterestingEntries: []string{
			fmt.Sprintf("%d wp-admin asset(s) on wp-login.php stamped ?ver=%s", bestN, best),
		},
	}
}

func fingerprintVersion(ctx context.Context, client *httpclient.Client, target *Target) *model.WPVersion {
	var fingerprints map[string]map[string][]string
	if err := json.Unmarshal(data.WPFingerprints(), &fingerprints); err != nil {
		return nil
	}

	var matchedSets [][]string
	votes := make(map[string]int)
	checked := 0

	for filePath, hashMap := range fingerprints {
		if len(hashMap) == 0 {
			continue
		}

		resp, err := client.Get(ctx, target.EffectiveURL+filePath)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		checked++

		hash := fmt.Sprintf("%x", md5.Sum(resp.Body))
		if versions, ok := hashMap[hash]; ok {
			matchedSets = append(matchedSets, versions)
			for _, v := range versions {
				votes[v]++
			}
		}
	}

	if len(matchedSets) == 0 {
		return nil
	}

	// A fingerprint match is a *set* of releases that share that exact file, so
	// the answer is the set of releases consistent with every matched asset -
	// their intersection - not a single point. Reporting one number implied false
	// precision and, when picked at random from a tie, was simply wrong.
	candidates := intersectVersionSets(matchedSets)
	ambiguousFallback := false
	if len(candidates) == 0 {
		// No single release satisfies every asset (a CDN or host modified one).
		// Fall back to the releases with the most agreement.
		candidates = topVoted(votes)
		ambiguousFallback = true
	}
	sortVersionsAsc(candidates)
	low, high := candidates[0], candidates[len(candidates)-1]

	// Report the newest consistent release: identical assets across a range mean
	// "this version or newer", and the newest estimate avoids flagging vulns that
	// were already patched in a later point release (the failure that tagged a
	// 7.1.x box with 4.7.x "RCEs").
	best := high

	confidence := 60
	switch {
	case len(matchedSets) >= 3:
		confidence = 90
	case len(matchedSets) == 2:
		confidence = 80
	}
	if ambiguousFallback {
		confidence = 50
	}
	if low != high && confidence > 70 {
		confidence = 70
	}

	entries := []string{fmt.Sprintf("matched %d of %d fingerprint file(s)", len(matchedSets), checked)}
	if low != high {
		entries = append(entries, fmt.Sprintf("consistent with %s - %s (fingerprints cannot separate these)", low, high))
	}
	if dbMax := maxFingerprintVersion(fingerprints); dbMax != "" && model.CompareVersions(high, dbMax) >= 0 {
		entries = append(entries, fmt.Sprintf("at the fingerprint DB ceiling (newest known: %s); the target may be newer - run `ghostpress update`", dbMax))
	}

	return &model.WPVersion{
		Number:             best,
		FoundBy:            "Fingerprinting (Aggressive)",
		Confidence:         confidence,
		InterestingEntries: entries,
	}
}

// modalVersion returns the most frequent version in counts; ties break toward
// the highest version, so the result is deterministic and never under-reports
// when two stamps are equally common.
func modalVersion(counts map[string]int) (string, int) {
	keys := make([]string, 0, len(counts))
	for v := range counts {
		keys = append(keys, v)
	}
	sortVersionsAsc(keys)
	best, bestN := "", 0
	for _, v := range keys {
		if counts[v] >= bestN {
			best, bestN = v, counts[v]
		}
	}
	return best, bestN
}

// intersectVersionSets returns the versions present in every set.
func intersectVersionSets(sets [][]string) []string {
	if len(sets) == 0 {
		return nil
	}
	counts := make(map[string]int)
	for _, s := range sets {
		seen := make(map[string]bool, len(s))
		for _, v := range s {
			if !seen[v] {
				seen[v] = true
				counts[v]++
			}
		}
	}
	var out []string
	for v, c := range counts {
		if c == len(sets) {
			out = append(out, v)
		}
	}
	return out
}

// topVoted returns the versions sharing the highest vote count.
func topVoted(votes map[string]int) []string {
	top := 0
	for _, c := range votes {
		if c > top {
			top = c
		}
	}
	var out []string
	for v, c := range votes {
		if c == top {
			out = append(out, v)
		}
	}
	return out
}

func sortVersionsAsc(vs []string) {
	sort.Slice(vs, func(i, j int) bool {
		return model.CompareVersions(vs[i], vs[j]) < 0
	})
}

func maxFingerprintVersion(fp map[string]map[string][]string) string {
	hi := ""
	for _, hashMap := range fp {
		for _, versions := range hashMap {
			for _, v := range versions {
				if hi == "" || model.CompareVersions(v, hi) > 0 {
					hi = v
				}
			}
		}
	}
	return hi
}

func lookupWPVulns(version string) []model.Vulnerability {
	var vulns []model.Vulnerability
	// Core vulns may be stored under a single "wordpress" bucket (Wordfence
	// data, with absolute ranges) or under major.minor branch keys (legacy
	// NVD-built data, with fixed_in). Scan all buckets; AffectsVersion handles
	// both shapes.
	for branch, vlist := range vulnDB().WordPress {
		for _, v := range vlist {
			if v.AffectsVersion(version) {
				if branch != "" && branch != "wordpress" {
					v.Title = fmt.Sprintf("[WP %s] %s", branch, v.Title)
				}
				vulns = append(vulns, v)
			}
		}
	}
	return vulns
}
