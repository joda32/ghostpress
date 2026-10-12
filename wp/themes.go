package wp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"ghostpress/data"
	"ghostpress/httpclient"
	"ghostpress/model"
)

func DetectMainTheme(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode) *model.Theme {
	body := string(target.Homepage)

	pattern := fmt.Sprintf(`(?i)/%s/themes/(%s)/style\.css`, regexp.QuoteMeta(target.ContentDir), slugCharClass)
	re := regexp.MustCompile(pattern)
	if m := re.FindStringSubmatch(body); len(m) > 1 {
		theme := &model.Theme{
			Slug:       m[1],
			Location:   target.ThemeURL(m[1]),
			FoundBy:    "CSS Style In Homepage (Passive)",
			Confidence: 80,
		}
		detectThemeVersion(ctx, client, target, theme)
		if theme.Version == "" {
			if v := versionFromHomepageAssets(target, "themes", theme.Slug); v != "" {
				theme.Version = v
				theme.VersionBlocked = false
				debugf("theme %s: version %s from homepage ?ver= asset (fallback)", theme.Slug, v)
			}
		}
		assignThemeVulns(theme)
		return theme
	}

	pattern = fmt.Sprintf(`(?i)/%s/themes/(%s)/`, regexp.QuoteMeta(target.ContentDir), slugCharClass)
	re = regexp.MustCompile(pattern)
	if m := re.FindStringSubmatch(body); len(m) > 1 {
		theme := &model.Theme{
			Slug:       m[1],
			Location:   target.ThemeURL(m[1]),
			FoundBy:    "URLs In Homepage (Passive)",
			Confidence: 70,
		}
		detectThemeVersion(ctx, client, target, theme)
		if theme.Version == "" {
			if v := versionFromHomepageAssets(target, "themes", theme.Slug); v != "" {
				theme.Version = v
				theme.VersionBlocked = false
				debugf("theme %s: version %s from homepage ?ver= asset (fallback)", theme.Slug, v)
			}
		}
		assignThemeVulns(theme)
		return theme
	}

	return nil
}

func EnumerateThemes(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode, mainTheme *model.Theme, slugsFile string) []model.Theme {
	found := make(map[string]*model.Theme)

	if mainTheme != nil {
		found[mainTheme.Slug] = mainTheme
	}

	if mode != model.ModeAggressive {
		for _, t := range passiveThemeFinders(target) {
			if _, exists := found[t.Slug]; !exists {
				cp := t
				found[t.Slug] = &cp
			}
		}
	}

	if mode != model.ModePassive {
		slugs := themeSlugsToCheck(slugsFile)
		for _, t := range aggressiveThemeFinders(ctx, client, target, slugs) {
			if _, exists := found[t.Slug]; !exists {
				cp := t
				found[t.Slug] = &cp
			}
		}
	}

	var results []model.Theme
	for _, t := range found {
		if t.Version == "" && !t.VersionBlocked {
			detectThemeVersion(ctx, client, target, t)
		}
		if t.Version == "" {
			if v := versionFromHomepageAssets(target, "themes", t.Slug); v != "" {
				t.Version = v
				t.VersionBlocked = false
				debugf("theme %s: version %s from homepage ?ver= asset (fallback)", t.Slug, v)
			}
		}
		if len(t.Vulnerabilities) == 0 && t.KnownVulnCount == 0 {
			assignThemeVulns(t)
		}
		results = append(results, *t)
	}
	return results
}

// assignThemeVulns attaches vulnerabilities for a theme, except when the version
// could not be determined — then it stashes the known vulns under
// UnconfirmedVulns (and records the count) instead of presenting them as
// confirmed findings.
func assignThemeVulns(t *model.Theme) {
	if t.VersionBlocked {
		t.UnconfirmedVulns = lookupThemeVulns(t.Slug, "")
		t.KnownVulnCount = len(t.UnconfirmedVulns)
		return
	}
	t.Vulnerabilities = lookupThemeVulns(t.Slug, t.Version)
}

func themeSlugsToCheck(customFile string) []string {
	if customFile != "" {
		if slugs, err := loadSlugFile(customFile); err == nil && len(slugs) > 0 {
			return slugs
		}
	}
	return data.PopularThemes()
}

func passiveThemeFinders(target *Target) []model.Theme {
	var themes []model.Theme
	body := string(target.Homepage)

	pattern := fmt.Sprintf(`(?i)/%s/themes/(%s)/`, regexp.QuoteMeta(target.ContentDir), slugCharClass)
	re := regexp.MustCompile(pattern)
	seen := make(map[string]bool)

	for _, match := range re.FindAllStringSubmatch(body, -1) {
		slug := match[1]
		if seen[slug] {
			continue
		}
		seen[slug] = true
		themes = append(themes, model.Theme{
			Slug:       slug,
			Location:   target.ThemeURL(slug),
			FoundBy:    "URLs In Homepage (Passive)",
			Confidence: 80,
		})
	}

	return themes
}

func aggressiveThemeFinders(ctx context.Context, client *httpclient.Client, target *Target, slugs []string) []model.Theme {
	var themes []model.Theme

	urls := make([]string, len(slugs))
	for i, slug := range slugs {
		urls[i] = target.ThemeURL(slug) + "style.css"
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

			if r.Response.StatusCode != 200 || target.IsSoft404(r.Response) {
				continue
			}

			body := string(r.Response.Body)
			if !strings.Contains(body, "Theme Name") {
				continue
			}

			themes = append(themes, model.Theme{
				Slug:       slugs[idx],
				Location:   target.ThemeURL(slugs[idx]),
				FoundBy:    "Known Locations (Aggressive)",
				Confidence: 80,
			})
		}
	}

	return themes
}

func detectThemeVersion(ctx context.Context, client *httpclient.Client, target *Target, theme *model.Theme) {
	styleURL := target.ThemeURL(theme.Slug) + "style.css"
	resp, err := client.Get(ctx, styleURL)
	if err != nil {
		theme.VersionBlocked = true
		debugf("theme %s: style.css request failed (%v) — version could not be confirmed", theme.Slug, err)
		return
	}
	if resp.StatusCode != 200 {
		if isBlockedStatus(resp.StatusCode) {
			theme.VersionBlocked = true
			debugf("theme %s: style.css HTTP %d — version detection blocked", theme.Slug, resp.StatusCode)
		}
		return
	}

	parseStyleCSS(string(resp.Body), theme)
	if theme.Version == "" && notRealFile(resp, target) {
		theme.VersionBlocked = true
		debugf("theme %s: style.css 200 but HTML/soft-404 — version not accessible", theme.Slug)
	}
}

func parseStyleCSS(body string, theme *model.Theme) {
	fields := map[string]*string{
		"Version":    &theme.Version,
		"Theme Name": &theme.StyleName,
		"Theme URI":  &theme.StyleURI,
		"Author":     &theme.Author,
		"Author URI": &theme.AuthorURI,
	}

	for field, target := range fields {
		re := regexp.MustCompile(fmt.Sprintf(`(?i)%s:\s*(.+)`, regexp.QuoteMeta(field)))
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			*target = strings.TrimSpace(m[1])
		}
	}
}

func lookupThemeVulns(slug, version string) []model.Vulnerability {
	vulnList, ok := vulnDB().Themes[slug]
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
