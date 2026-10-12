package wp

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"regexp"

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

	if len(candidates) == 0 {
		return nil
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.Confidence > best.Confidence {
			best = c
		}
	}

	if best.Confidence < 40 {
		return nil
	}

	best.Vulnerabilities = lookupWPVulns(best.Number)
	if best.Number != "" {
		best.Status = "insecure"
	}

	return &best
}

func passiveVersionFinders(target *Target) []model.WPVersion {
	var results []model.WPVersion
	body := string(target.Homepage)

	metaRe := regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)["']`)
	if m := metaRe.FindStringSubmatch(body); len(m) > 1 {
		results = append(results, model.WPVersion{
			Number:     m[1],
			FoundBy:    "Meta Generator (Passive)",
			Confidence: 80,
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
				Number:     m[1],
				FoundBy:    fp.name + " (Passive)",
				Confidence: 80,
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
				Number:     m[1],
				FoundBy:    fp.name + " (Aggressive)",
				Confidence: 90,
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
				Number:     m[1],
				FoundBy:    "Readme (Aggressive)",
				Confidence: 90,
				InterestingEntries: []string{target.EffectiveURL + "readme.html"},
			})
		}
	}

	if ver := fingerprintVersion(ctx, client, target); ver != nil {
		results = append(results, *ver)
	}

	return results
}

func fingerprintVersion(ctx context.Context, client *httpclient.Client, target *Target) *model.WPVersion {
	var fingerprints map[string]map[string][]string
	if err := json.Unmarshal(data.WPFingerprintsRaw, &fingerprints); err != nil {
		return nil
	}

	versionVotes := make(map[string]int)
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
			for _, v := range versions {
				versionVotes[v]++
			}
		}
	}

	if len(versionVotes) == 0 {
		return nil
	}

	var bestVersion string
	bestCount := 0
	tiedTop := 0
	for v, count := range versionVotes {
		if count > bestCount {
			bestVersion = v
			bestCount = count
			tiedTop = 1
		} else if count == bestCount {
			tiedTop++
		}
	}

	// Confidence reflects the weight of evidence: a single file matching many
	// releases is weak, while several files converging on one release is
	// strong. A tie at the top means the fingerprints are ambiguous.
	confidence := 60
	switch {
	case bestCount >= 3:
		confidence = 100
	case bestCount == 2:
		confidence = 85
	}
	if tiedTop > 1 && confidence > 50 {
		confidence = 50
	}

	return &model.WPVersion{
		Number:     bestVersion,
		FoundBy:    "Fingerprinting (Aggressive)",
		Confidence: confidence,
		InterestingEntries: []string{fmt.Sprintf("matched %d of %d fingerprint file(s)", bestCount, checked)},
	}
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
