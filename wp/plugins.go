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
		p.Vulnerabilities = lookupPluginVulns(p.Slug, p.Version)
		results = append(results, *p)
	}
	return results
}

func passivePluginFinders(target *Target) []model.Plugin {
	var plugins []model.Plugin
	body := string(target.Homepage)

	pattern := fmt.Sprintf(`(?i)/%s/plugins/([^/]+)/`, regexp.QuoteMeta(target.ContentDir))
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

func aggressivePluginFinders(ctx context.Context, client *httpclient.Client, target *Target, slugs []string) []model.Plugin {
	var plugins []model.Plugin

	urls := make([]string, len(slugs))
	for i, slug := range slugs {
		urls[i] = target.PluginURL(slug)
	}

	batchSize := 50
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}

		results := client.BulkGet(ctx, urls[i:end])
		for j, r := range results {
			if r.Error != nil || r.Response == nil {
				continue
			}

			idx := i + j
			slug := slugs[idx]

			if r.Response.StatusCode == 403 {
				plugins = append(plugins, model.Plugin{
					Slug:       slug,
					Location:   urls[idx],
					FoundBy:    "Known Locations (Aggressive)",
					Confidence: 80,
				})
				continue
			}

			if r.Response.StatusCode == 200 && !target.IsSoft404(r.Response) {
				if isDirectoryListing(string(r.Response.Body)) {
					plugins = append(plugins, model.Plugin{
						Slug:             slug,
						Location:         urls[idx],
						FoundBy:          "Known Locations (Aggressive)",
						Confidence:       100,
						DirectoryListing: true,
					})
				}
			}
		}
	}

	// also check via readme.txt for plugins not yet found
	foundSlugs := make(map[string]bool)
	for _, p := range plugins {
		foundSlugs[p.Slug] = true
	}
	var readmeURLs []string
	var readmeSlugs []string
	for _, slug := range slugs {
		if foundSlugs[slug] {
			continue
		}
		readmeURLs = append(readmeURLs, target.PluginURL(slug)+"readme.txt")
		readmeSlugs = append(readmeSlugs, slug)
	}

	for i := 0; i < len(readmeURLs); i += batchSize {
		end := i + batchSize
		if end > len(readmeURLs) {
			end = len(readmeURLs)
		}
		results := client.BulkGet(ctx, readmeURLs[i:end])
		for j, r := range results {
			if r.Error != nil || r.Response == nil || r.Response.StatusCode != 200 {
				continue
			}
			ct := r.Response.Headers.Get("Content-Type")
			if strings.Contains(ct, "text/html") {
				continue
			}
			body := string(r.Response.Body)
			if strings.Contains(body, "=== ") || strings.Contains(body, "Stable tag:") {
				idx := i + j
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

func detectPluginVersion(ctx context.Context, client *httpclient.Client, target *Target, plugin *model.Plugin) {
	readmeURL := target.PluginURL(plugin.Slug) + "readme.txt"
	resp, err := client.Get(ctx, readmeURL)
	if err == nil && resp.StatusCode == 200 {
		body := string(resp.Body)

		stableRe := regexp.MustCompile(`(?i)stable\s*tag:\s*([\d.]+)`)
		if m := stableRe.FindStringSubmatch(body); len(m) > 1 && m[1] != "trunk" {
			plugin.Version = m[1]
			plugin.InterestingEntries = append(plugin.InterestingEntries, readmeURL)
			return
		}
	}

	changelogURL := target.PluginURL(plugin.Slug) + "changelog.txt"
	resp, err = client.Get(ctx, changelogURL)
	if err == nil && resp.StatusCode == 200 {
		re := regexp.MustCompile(`(?m)^=+\s*([\d.]+)\s*=`)
		if m := re.FindStringSubmatch(string(resp.Body)); len(m) > 1 {
			plugin.Version = m[1]
			return
		}
	}
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
