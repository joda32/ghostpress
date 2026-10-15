package wp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ghostpress/httpclient"
	"ghostpress/model"
)

func EnumerateUsers(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode, rangeStr string) []model.User {
	found := make(map[string]*model.User)

	if mode != model.ModeAggressive {
		for _, u := range passiveUserFinders(target) {
			if _, exists := found[u.Username]; !exists {
				cp := u
				found[u.Username] = &cp
			}
		}
	}

	if mode != model.ModePassive {
		maxID := 10
		if rangeStr != "" {
			if n, err := strconv.Atoi(rangeStr); err == nil {
				maxID = n
			}
		}

		for _, u := range aggressiveUserFinders(ctx, client, target, maxID) {
			if existing, exists := found[u.Username]; exists {
				if u.Confidence > existing.Confidence {
					found[u.Username] = &u
				}
			} else {
				cp := u
				found[u.Username] = &cp
			}
		}
	}

	var results []model.User
	for _, u := range found {
		results = append(results, *u)
	}
	debugf("users: %d unique after merge/dedup", len(results))
	return results
}

func passiveUserFinders(target *Target) []model.User {
	var users []model.User
	body := string(target.Homepage)

	authorRe := regexp.MustCompile(`(?i)/author/([^/"']+)/`)
	seen := make(map[string]bool)
	for _, m := range authorRe.FindAllStringSubmatch(body, -1) {
		username := m[1]
		if seen[username] {
			continue
		}
		seen[username] = true
		users = append(users, model.User{
			Username:   username,
			FoundBy:    "Author Posts (Passive)",
			Confidence: 70,
		})
	}

	// WordPress adds `author-<nicename>` to the <body> tag on author archive
	// pages. Scope strictly to the body tag's class list - matching author-*
	// anywhere on the page harvests generic component classes (author-box,
	// author-name, author-avatar, …) as bogus usernames.
	if bt := bodyOpenTagRe.FindStringSubmatch(body); len(bt) > 1 {
		for _, cls := range strings.Fields(bt[1]) {
			m := authorBodyClassRe.FindStringSubmatch(cls)
			if len(m) < 2 || seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			users = append(users, model.User{
				Username:   m[1],
				FoundBy:    "Author Body Class (Passive)",
				Confidence: 60,
			})
		}
	}

	debugf("users: %d from passive homepage finders", len(users))
	return users
}

var (
	bodyOpenTagRe = regexp.MustCompile(`(?i)<body[^>]*\bclass=["']([^"']*)["']`)
	// Exactly author-<nicename>; leading letter excludes the numeric
	// author-<id> body class.
	authorBodyClassRe = regexp.MustCompile(`(?i)^author-([a-z][a-z0-9_-]*)$`)
)

func aggressiveUserFinders(ctx context.Context, client *httpclient.Client, target *Target, maxID int) []model.User {
	var users []model.User

	apiUsers := wpJSONAPIUsers(ctx, client, target)
	debugf("users: %d from WP JSON API", len(apiUsers))
	users = append(users, apiUsers...)

	oembedUsers := oembedAPIUsers(ctx, client, target)
	debugf("users: %d from oembed API", len(oembedUsers))
	users = append(users, oembedUsers...)

	sitemapUsers := authorSitemapUsers(ctx, client, target)
	debugf("users: %d from author sitemap(s)", len(sitemapUsers))
	users = append(users, sitemapUsers...)

	bruteUsers := authorIDBrute(ctx, client, target, maxID)
	debugf("users: %d from author-id brute force", len(bruteUsers))
	users = append(users, bruteUsers...)

	return users
}

func wpJSONAPIUsers(ctx context.Context, client *httpclient.Client, target *Target) []model.User {
	var allUsers []model.User

	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("%swp-json/wp/v2/users?per_page=100&page=%d", target.EffectiveURL, page)
		resp, err := client.Get(ctx, url)
		if err != nil || resp.StatusCode != 200 {
			break
		}

		var apiUsers []struct {
			ID   int    `json:"id"`
			Slug string `json:"slug"`
			Name string `json:"name"`
		}

		if err := json.Unmarshal(resp.Body, &apiUsers); err != nil {
			break
		}

		for _, u := range apiUsers {
			allUsers = append(allUsers, model.User{
				ID:         u.ID,
				Username:   u.Slug,
				FoundBy:    "WP JSON API (Aggressive)",
				Confidence: 100,
			})
		}

		if len(apiUsers) < 100 {
			break
		}
	}

	return allUsers
}

func oembedAPIUsers(ctx context.Context, client *httpclient.Client, target *Target) []model.User {
	url := target.EffectiveURL + "wp-json/oembed/1.0/embed?url=" + target.EffectiveURL
	resp, err := client.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	var result struct {
		AuthorName string `json:"author_name"`
		AuthorURL  string `json:"author_url"`
	}
	if err := json.Unmarshal(resp.Body, &result); err != nil || result.AuthorName == "" {
		return nil
	}

	username := result.AuthorName
	if result.AuthorURL != "" {
		re := regexp.MustCompile(`/author/([^/]+)/?`)
		if m := re.FindStringSubmatch(result.AuthorURL); len(m) > 1 {
			username = m[1]
		}
	}

	return []model.User{{
		Username:   username,
		FoundBy:    "Oembed API (Aggressive)",
		Confidence: 90,
	}}
}

func authorSitemapUsers(ctx context.Context, client *httpclient.Client, target *Target) []model.User {
	var users []model.User
	re := regexp.MustCompile(`<loc>[^<]*/author/([^/<]+)/?</loc>`)

	extract := func(body string) int {
		ms := re.FindAllStringSubmatch(body, -1)
		for _, m := range ms {
			users = append(users, model.User{
				Username:   m[1],
				FoundBy:    "Author Sitemap (Aggressive)",
				Confidence: 100,
			})
		}
		return len(ms)
	}

	// Core user sitemaps are paginated (wp-sitemap-users-1.xml, -2, …), ~2000
	// entries each. Follow the pages until one is missing or yields nothing.
	const maxPages = 50
	for page := 1; page <= maxPages; page++ {
		url := fmt.Sprintf("%swp-sitemap-users-%d.xml", target.EffectiveURL, page)
		resp, err := client.Get(ctx, url)
		if err != nil || resp.StatusCode != 200 {
			break
		}
		if notRealFile(resp, target) {
			debugf("users: %s 200 but HTML/soft-404 - not a real sitemap, skipping", url)
			break
		}
		n := extract(string(resp.Body))
		debugf("users: wp-sitemap-users-%d.xml -> %d entries", page, n)
		if n == 0 {
			break
		}
	}

	// Legacy / plugin author sitemap.
	if resp, err := client.Get(ctx, target.EffectiveURL+"author-sitemap.xml"); err == nil && resp.StatusCode == 200 && !notRealFile(resp, target) {
		extract(string(resp.Body))
	}

	if len(users) > 500 {
		debugf("users: author sitemap(s) returned %d entries - large author list, output may be voluminous", len(users))
	}
	return users
}

func authorIDBrute(ctx context.Context, client *httpclient.Client, target *Target, maxID int) []model.User {
	var users []model.User

	urls := make([]string, maxID)
	for i := 0; i < maxID; i++ {
		urls[i] = fmt.Sprintf("%s?author=%d", target.EffectiveURL, i+1)
	}

	results := client.BulkGet(ctx, urls)
	for i, r := range results {
		if r.Error != nil || r.Response == nil {
			continue
		}

		if r.Response.StatusCode == 301 || r.Response.StatusCode == 302 {
			location := r.Response.Headers.Get("Location")
			re := regexp.MustCompile(`/author/([^/]+)/?`)
			if m := re.FindStringSubmatch(location); len(m) > 1 {
				users = append(users, model.User{
					ID:         i + 1,
					Username:   m[1],
					FoundBy:    "Author ID Brute Forcing (Aggressive)",
					Confidence: 100,
				})
			}
			continue
		}

		if r.Response.StatusCode == 200 && !target.IsSoft404(r.Response) {
			body := string(r.Response.Body)
			username := extractAuthorFromBody(body)
			if username != "" {
				users = append(users, model.User{
					ID:         i + 1,
					Username:   username,
					FoundBy:    "Author ID Brute Forcing (Aggressive)",
					Confidence: 70,
				})
			}
		}
	}

	return users
}

func extractAuthorFromBody(body string) string {
	re := regexp.MustCompile(`(?i)class="[^"]*\bauthor\b[^"]*author-([a-zA-Z][a-zA-Z0-9_-]*)[^"]*"`)
	if m := re.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}

	re2 := regexp.MustCompile(`(?i)/author/([a-zA-Z][a-zA-Z0-9_-]*)/?["']`)
	if m := re2.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}

	return ""
}

func LoginErrorUsers(ctx context.Context, client *httpclient.Client, target *Target, usernames []string) []model.User {
	var confirmed []model.User

	for _, username := range usernames {
		loginURL := target.LoginURL("")
		postData := fmt.Sprintf("log=%s&pwd=ghostpress_invalid_check_only&wp-submit=Log+In", username)
		resp, err := client.Post(ctx, loginURL, "application/x-www-form-urlencoded", []byte(postData))
		if err != nil {
			continue
		}

		body := strings.ToLower(string(resp.Body))
		if strings.Contains(body, "incorrect password") ||
			strings.Contains(body, "the password you entered") ||
			strings.Contains(body, "is not correct") {
			confirmed = append(confirmed, model.User{
				Username:   username,
				FoundBy:    "Login Error Messages (Aggressive)",
				Confidence: 100,
			})
		}
	}

	return confirmed
}
