package wp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"ghostpress/httpclient"
	"ghostpress/model"
)

// EnumerateMedia discovers uploaded media / attachments.
//
// Passive: harvests wp-content/uploads URLs already present in the homepage.
// Aggressive: queries the REST media endpoint and brute-forces attachment IDs
// via ?attachment_id=N, resolving each to its upload URL.
func EnumerateMedia(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode, rangeStr string) []model.Media {
	found := make(map[string]*model.Media)

	add := func(m model.Media) {
		if m.URL == "" {
			return
		}
		if existing, ok := found[m.URL]; ok {
			if m.Confidence > existing.Confidence {
				found[m.URL] = &m
			}
			return
		}
		cp := m
		found[m.URL] = &cp
	}

	if mode != model.ModeAggressive {
		for _, m := range passiveMediaFinders(target) {
			add(m)
		}
	}

	if mode != model.ModePassive {
		for _, m := range restAPIMedia(ctx, client, target) {
			add(m)
		}

		maxID := 50
		if rangeStr != "" {
			if n, err := strconv.Atoi(rangeStr); err == nil && n > 0 {
				maxID = n
			}
		}
		for _, m := range attachmentIDBrute(ctx, client, target, maxID) {
			add(m)
		}
	}

	results := make([]model.Media, 0, len(found))
	for _, m := range found {
		results = append(results, *m)
	}
	return results
}

var uploadsURLRe = regexp.MustCompile(`https?://[^"'\s)]+/` + `wp-content/uploads/[^"'\s)]+`)

func passiveMediaFinders(target *Target) []model.Media {
	var media []model.Media
	body := string(target.Homepage)

	seen := make(map[string]bool)
	for _, u := range uploadsURLRe.FindAllString(body, -1) {
		if seen[u] {
			continue
		}
		seen[u] = true
		media = append(media, model.Media{
			URL:        u,
			FoundBy:    "URLs In Homepage (Passive)",
			Confidence: 60,
		})
	}

	return media
}

func restAPIMedia(ctx context.Context, client *httpclient.Client, target *Target) []model.Media {
	var media []model.Media

	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("%swp-json/wp/v2/media?per_page=100&page=%d", target.EffectiveURL, page)
		resp, err := client.Get(ctx, url)
		if err != nil || resp.StatusCode != 200 {
			break
		}

		var items []struct {
			ID        int    `json:"id"`
			SourceURL string `json:"source_url"`
			Title     struct {
				Rendered string `json:"rendered"`
			} `json:"title"`
		}
		if err := json.Unmarshal(resp.Body, &items); err != nil {
			break
		}

		for _, it := range items {
			if it.SourceURL == "" {
				continue
			}
			media = append(media, model.Media{
				URL:        it.SourceURL,
				Title:      it.Title.Rendered,
				FoundBy:    "WP JSON API (Aggressive)",
				Confidence: 100,
			})
		}

		if len(items) < 100 {
			break
		}
	}

	return media
}

func attachmentIDBrute(ctx context.Context, client *httpclient.Client, target *Target, maxID int) []model.Media {
	var media []model.Media

	urls := make([]string, maxID)
	for i := 0; i < maxID; i++ {
		urls[i] = fmt.Sprintf("%s?attachment_id=%d", target.EffectiveURL, i+1)
	}

	results := client.BulkGet(ctx, urls)
	for _, r := range results {
		if r.Error != nil || r.Response == nil {
			continue
		}

		// A redirect to the upload file resolves the attachment directly.
		if r.Response.StatusCode == 301 || r.Response.StatusCode == 302 {
			loc := r.Response.Headers.Get("Location")
			if m := uploadsURLRe.FindString(loc); m != "" {
				media = append(media, model.Media{
					URL:        m,
					FoundBy:    "Attachment ID Brute Forcing (Aggressive)",
					Confidence: 90,
				})
			}
			continue
		}

		if r.Response.StatusCode == 200 && !target.IsSoft404(r.Response) {
			if m := uploadsURLRe.FindString(string(r.Response.Body)); m != "" {
				media = append(media, model.Media{
					URL:        m,
					FoundBy:    "Attachment ID Brute Forcing (Aggressive)",
					Confidence: 70,
				})
			}
		}
	}

	return media
}
