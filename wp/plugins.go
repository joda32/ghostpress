package wp

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"ghostpress/data"
	"ghostpress/httpclient"
	"ghostpress/model"
)

func EnumeratePlugins(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode, slugsFile string) []model.Plugin {
	found := make(map[string]*model.Plugin)

	if mode != model.ModeAggressive {
		for _, p := range passivePluginFinders(target) {
			if _, exists := found[p.Slug]; !exists {
				cp := p
				found[p.Slug] = &cp
			}
		}
	}

	if mode != model.ModePassive {
		slugs := pluginSlugsToCheck(slugsFile)
		for _, p := range aggressivePluginFinders(ctx, client, target, slugs) {
			if existing, exists := found[p.Slug]; exists {
				if p.Confidence > existing.Confidence {
					found[p.Slug] = &p
				}
			} else {
				cp := p
				found[p.Slug] = &cp
			}
		}
	}

	var results []model.Plugin
	for _, p := range found {
		detectPluginVersion(ctx, client, target, p)
		if p.Version == "" {
			if v := versionFromHomepageAssets(target, "plugins", p.Slug); v != "" {
				p.Version = v
				p.VersionBlocked = false
				debugf("plugin %s: version %s from homepage ?ver= asset (fallback)", p.Slug, v)
			}
		}
		if p.VersionBlocked {
			// Version couldn't be determined (WAF block, soft-404, or transport
			// error) - do not present the full historical vuln list as live
			// findings. Keep the known list under UnconfirmedVulns so a report (or
			// --show-unconfirmed) can surface them, flagged as unconfirmed.
			p.UnconfirmedVulns = lookupPluginVulns(p.Slug, "")
			p.KnownVulnCount = len(p.UnconfirmedVulns)
		} else {
			p.Vulnerabilities = lookupPluginVulns(p.Slug, p.Version)
		}
		debugf("plugin %s: version=%q vulns=%d blocked=%v known=%d found-by=%q", p.Slug, p.Version, len(p.Vulnerabilities), p.VersionBlocked, p.KnownVulnCount, p.FoundBy)
		results = append(results, *p)
	}
	return results
}

func passivePluginFinders(target *Target) []model.Plugin {
	var plugins []model.Plugin
	body := string(target.Homepage)

	pattern := fmt.Sprintf(`(?i)/%s/plugins/(%s)/`, regexp.QuoteMeta(target.ContentDir), slugCharClass)
	re := regexp.MustCompile(pattern)
	seen := make(map[string]bool)

	for _, match := range re.FindAllStringSubmatch(body, -1) {
		slug := match[1]
		if seen[slug] {
			continue
		}
		seen[slug] = true
		plugins = append(plugins, model.Plugin{
			Slug:       slug,
			Location:   target.PluginURL(slug),
			FoundBy:    "URLs In Homepage (Passive)",
			Confidence: 80,
		})
	}

	return plugins
}

// probeBodyCap bounds how much of a probe response (plugin dir index, readme.txt,
// style.css) is buffered: the markers we look for ("Index of", "Stable tag:",
// "Theme Name") are all near the top, so there's no need to read a large
// soft-404 / error page in full.
const probeBodyCap = 64 * 1024

const pluginBatchSize = 50

func aggressivePluginFinders(ctx context.Context, client *httpclient.Client, target *Target, slugs []string) []model.Plugin {
	var plugins []model.Plugin
	foundSlugs := make(map[string]bool)

	urls := make([]string, len(slugs))
	for i, slug := range slugs {
		urls[i] = target.PluginURL(slug)
	}

	// Phase 1: HEAD each plugin directory (no body). A 403 is a positive hit
	// (dir exists, listing denied). A 200 is ambiguous - only those get a capped
	// GET to check for a directory listing. Everything else (usually 404) is
	// dropped without downloading the server's often-large error page.
	for i := 0; i < len(urls); i += pluginBatchSize {
		end := min(i+pluginBatchSize, len(urls))
		var getIdx []int
		for j, r := range client.BulkHead(ctx, urls[i:end]) {
			if r.Error != nil || r.Response == nil {
				continue
			}
			idx := i + j
			switch {
			case r.Response.StatusCode == 403:
				plugins = append(plugins, model.Plugin{
					Slug:       slugs[idx],
					Location:   urls[idx],
					FoundBy:    "Known Locations (Aggressive)",
					Confidence: 80,
				})
				foundSlugs[slugs[idx]] = true
			case r.Response.StatusCode == 200 || r.Response.StatusCode == 405 || r.Response.StatusCode == 501:
				getIdx = append(getIdx, idx)
			}
		}
		for k, r := range client.BulkGetCapped(ctx, urlsAt(urls, getIdx), probeBodyCap) {
			if r.Error != nil || r.Response == nil || r.Response.StatusCode != 200 {
				continue
			}
			if target.IsSoft404(r.Response) || !isDirectoryListing(string(r.Response.Body)) {
				continue
			}
			idx := getIdx[k]
			plugins = append(plugins, model.Plugin{
				Slug:             slugs[idx],
				Location:         urls[idx],
				FoundBy:          "Known Locations (Aggressive)",
				Confidence:       100,
				DirectoryListing: true,
			})
			foundSlugs[slugs[idx]] = true
		}
	}

	// Phase 2: for slugs not yet found, HEAD readme.txt. A non-HTML 200 is very
	// likely a real readme - confirm with a capped GET (only those few), so we
	// never pull a readme-shaped soft-404 body for every miss.
	var readmeURLs []string
	var readmeSlugs []string
	for _, slug := range slugs {
		if foundSlugs[slug] {
			continue
		}
		readmeURLs = append(readmeURLs, target.PluginURL(slug)+"readme.txt")
		readmeSlugs = append(readmeSlugs, slug)
	}
	for i := 0; i < len(readmeURLs); i += pluginBatchSize {
		end := min(i+pluginBatchSize, len(readmeURLs))
		var getIdx []int
		for j, r := range client.BulkHead(ctx, readmeURLs[i:end]) {
			if r.Error != nil || r.Response == nil || r.Response.StatusCode != 200 {
				continue
			}
			if strings.Contains(strings.ToLower(r.Response.Headers.Get("Content-Type")), "text/html") {
				continue // soft-404 HTML page, not a readme
			}
			getIdx = append(getIdx, i+j)
		}
		for k, r := range client.BulkGetCapped(ctx, urlsAt(readmeURLs, getIdx), probeBodyCap) {
			if r.Error != nil || r.Response == nil || r.Response.StatusCode != 200 {
				continue
			}
			body := string(r.Response.Body)
			if strings.Contains(body, "=== ") || strings.Contains(body, "Stable tag:") {
				idx := getIdx[k]
				plugins = append(plugins, model.Plugin{
					Slug:       readmeSlugs[idx],
					Location:   target.PluginURL(readmeSlugs[idx]),
					FoundBy:    "Known Locations (Aggressive)",
					Confidence: 70,
				})
			}
		}
	}

	return plugins
}

// urlsAt gathers the URLs at the given indices, preserving order.
func urlsAt(urls []string, idx []int) []string {
	out := make([]string, len(idx))
	for i, j := range idx {
		out[i] = urls[j]
	}
	return out
}

func detectPluginVersion(ctx context.Context, client *httpclient.Client, target *Target, plugin *model.Plugin) {
	blocked := false

	readmeURL := target.PluginURL(plugin.Slug) + "readme.txt"
	if resp, err := client.GetCapped(ctx, readmeURL, probeBodyCap); err != nil {
		blocked = true
		debugf("plugin %s: readme.txt request failed (%v) - treated as unreachable", plugin.Slug, err)
	} else if v := stableTagVersion(resp); v != "" {
		plugin.Version = v
		plugin.InterestingEntries = append(plugin.InterestingEntries, readmeURL)
		debugf("plugin %s: version %s from readme.txt", plugin.Slug, v)
		return
	} else if isBlockedStatus(resp.StatusCode) {
		blocked = true
		debugf("plugin %s: readme.txt HTTP %d - blocked", plugin.Slug, resp.StatusCode)
	} else if resp.StatusCode == 200 && notRealFile(resp, target) {
		blocked = true
		debugf("plugin %s: readme.txt 200 but HTML/soft-404 (%d bytes) - readme not accessible", plugin.Slug, len(resp.Body))
	} else {
		debugf("plugin %s: readme.txt HTTP %d, no 'Stable tag'", plugin.Slug, resp.StatusCode)
	}

	changelogURL := target.PluginURL(plugin.Slug) + "changelog.txt"
	if resp, err := client.GetCapped(ctx, changelogURL, probeBodyCap); err != nil {
		blocked = true
	} else if v := changelogVersion(resp); v != "" {
		plugin.Version = v
		debugf("plugin %s: version %s from changelog.txt", plugin.Slug, v)
		return
	} else if isBlockedStatus(resp.StatusCode) || (resp.StatusCode == 200 && notRealFile(resp, target)) {
		blocked = true
	}

	if blocked {
		plugin.VersionBlocked = true
		debugf("plugin %s: version could not be confirmed (readme/changelog blocked, soft-404, or unreachable) - vulns not reported as findings", plugin.Slug)
	} else {
		debugf("plugin %s: version not detected (vulns reported for ALL known versions)", plugin.Slug)
	}
}

// isBlockedStatus reports whether an HTTP status indicates the request was
// turned away by a WAF / rate limiter rather than answered on its merits.
func isBlockedStatus(code int) bool {
	return code == 429 || code == 403 || code == 503
}

var (
	stableTagRe  = regexp.MustCompile(`(?i)stable\s*tag:\s*([\d.]+)`)
	changelogRe  = regexp.MustCompile(`(?m)^=+\s*([\d.]+)\s*=`)
	assetVerTmpl = `(?i)/%s/%s/%s/[^"'?\s]+\?[^"'\s]*\bver=([0-9]+(?:\.[0-9]+)+)`
)

func stableTagVersion(resp *httpclient.Response) string {
	if resp.StatusCode != 200 {
		return ""
	}
	if m := stableTagRe.FindStringSubmatch(string(resp.Body)); len(m) > 1 && m[1] != "trunk" {
		return m[1]
	}
	return ""
}

func changelogVersion(resp *httpclient.Response) string {
	if resp.StatusCode != 200 {
		return ""
	}
	if m := changelogRe.FindStringSubmatch(string(resp.Body)); len(m) > 1 {
		return m[1]
	}
	return ""
}

// notRealFile reports whether a 200 response is not the plain-text file we asked
// for - i.e. an HTML soft-404 / security page - so it must not be parsed as a
// readme/style/changelog.
func notRealFile(resp *httpclient.Response, target *Target) bool {
	if strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "text/html") {
		return true
	}
	return target.IsSoft404(resp)
}

// versionFromHomepageAssets recovers a plugin/theme version from an enqueued
// asset's ?ver= query parameter in the homepage source (passive, no request).
// It is a fallback for when readme.txt/style.css are blocked or soft-404'd.
// kind is "plugins" or "themes".
//
// Two false sources are guarded against: a ?ver equal to the WordPress core
// version is WordPress's default stamp for assets enqueued without an explicit
// version (not the plugin's own version), so it is discarded; and when several
// distinct values appear (e.g. a bundled library on a different version) the
// most frequent one is chosen rather than the highest, since the component's
// own assets dominate by count.
func versionFromHomepageAssets(target *Target, kind, slug string) string {
	pattern := fmt.Sprintf(assetVerTmpl, regexp.QuoteMeta(target.ContentDir), kind, regexp.QuoteMeta(slug))
	re := regexp.MustCompile(pattern)

	counts := make(map[string]int)
	for _, m := range re.FindAllStringSubmatch(string(target.Homepage), -1) {
		v := m[1]
		if target.WPVersion != "" && v == target.WPVersion {
			continue // WordPress default ?ver=<core>, not the component's version
		}
		counts[v]++
	}

	best, bestCount := "", 0
	for v, c := range counts {
		if c > bestCount || (c == bestCount && model.CompareVersions(v, best) > 0) {
			best, bestCount = v, c
		}
	}
	return best
}

func pluginSlugsToCheck(customFile string) []string {
	if customFile != "" {
		if slugs, err := loadSlugFile(customFile); err == nil && len(slugs) > 0 {
			return slugs
		}
	}
	return data.PopularPlugins()
}

// loadSlugFile reads a slug list (one per line), trimming whitespace and
// skipping blank lines and '#' comments.
func loadSlugFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var slugs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		slugs = append(slugs, line)
	}
	return slugs, scanner.Err()
}

func lookupPluginVulns(slug, version string) []model.Vulnerability {
	vulnList, ok := vulnDB().Plugins[slug]
	if !ok {
		return nil
	}

	if version == "" {
		return vulnList
	}

	var applicable []model.Vulnerability
	for _, v := range vulnList {
		if v.AffectsVersion(version) {
			applicable = append(applicable, v)
		}
	}
	return applicable
}

func CheckPluginDirectoryListing(ctx context.Context, client *httpclient.Client, target *Target, plugin *model.Plugin) {
	resp, err := client.Get(ctx, plugin.Location)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	if isDirectoryListing(string(resp.Body)) {
		plugin.DirectoryListing = true
	}
}

func CheckPluginErrorLog(ctx context.Context, client *httpclient.Client, target *Target, plugin *model.Plugin) {
	url := plugin.Location + "error_log"
	resp, err := client.Head(ctx, url)
	if err != nil {
		return
	}
	if resp.StatusCode == 200 {
		plugin.ErrorLog = true
		plugin.InterestingEntries = append(plugin.InterestingEntries, url)
	}
}

func hasWPContent(body string, dir string) bool {
	return strings.Contains(body, "/"+dir+"/plugins/") || strings.Contains(body, "/"+dir+"/themes/")
}
