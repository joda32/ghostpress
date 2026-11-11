package wp

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"ghostpress/httpclient"
	"ghostpress/model"
)

// Version detection can be upgraded from inference to cryptographic proof using
// api.wordpress.org, which publishes a per-release file->md5 checksum manifest.
// This is online-only and opt-out: any network failure leaves the offline result
// untouched, so the scanner still works air-gapped. The target URL is never sent
// to wordpress.org - only version numbers are - so it leaks nothing about who is
// being scanned.

const wpAPIBase = "https://api.wordpress.org"

var wpAPIEnabled = true

// SetWPAPIEnabled toggles the api.wordpress.org checksum confirmation step.
func SetWPAPIEnabled(b bool) { wpAPIEnabled = b }

var (
	stableOnce sync.Once
	stableMap  map[string]string // version -> status ("latest"/"outdated"/...)

	manifestCache = map[string]map[string]string{} // version -> (path -> md5)
)

var probeablePath = regexp.MustCompile(`^wp-(?:admin|includes)/[^?]*\.(?:js|css)$`)

// confirmVersionViaChecksums tries to prove the target's exact WordPress release
// against api.wordpress.org. guess is the best offline estimate (may be empty).
// It returns a proven *model.WPVersion, or nil when it can't confirm (offline,
// unreachable, host-modified assets, or a version older than the search window).
func confirmVersionViaChecksums(ctx context.Context, client *httpclient.Client, target *Target, guess string) *model.WPVersion {
	if !wpAPIEnabled {
		return nil
	}
	stable := wpStableVersions(ctx)
	if len(stable) == 0 {
		return nil
	}

	// Candidate releases to verify, newest first. Newest-first matters: a file
	// unchanged between releases would otherwise be misattributed to an older one.
	candidates := recentReleases(stable, 8)
	if guess != "" && stable[guess] != "" && !contains(candidates, guess) {
		candidates = append(candidates, guess) // ensure a stale-DB guess is checked
		sortVersionsDesc(candidates)
	}

	for _, v := range candidates {
		pred := predecessor(stable, v)
		if pred == "" {
			continue
		}
		if ok, ev := verifyExact(ctx, client, target, v, pred); ok {
			entries := []string{"cryptographically verified against api.wordpress.org release checksums"}
			entries = append(entries, ev...)
			if stable[v] == "latest" {
				entries = append(entries, "this is the current WordPress release")
			}
			return &model.WPVersion{
				Number:             v,
				FoundBy:            "Checksum Verification (Aggressive)",
				Confidence:         100,
				InterestingEntries: entries,
			}
		}
	}
	return nil
}

// verifyExact confirms the target is release v (not its predecessor p) by probing
// files whose checksums differ between v and p and matching them to v's copies.
func verifyExact(ctx context.Context, client *httpclient.Client, target *Target, v, p string) (bool, []string) {
	mv := wpChecksums(ctx, v)
	mp := wpChecksums(ctx, p)
	if mv == nil || mp == nil {
		return false, nil
	}

	var discs []string
	for path, h := range mv {
		if hp, ok := mp[path]; ok && hp != h && probeablePath.MatchString(path) {
			discs = append(discs, path)
		}
	}
	if len(discs) == 0 {
		return false, nil // v and p share these assets - can't tell them apart here
	}
	sort.Strings(discs)
	if len(discs) > 4 {
		discs = discs[:4]
	}

	vMatch, pMatch := 0, 0
	var evidence []string
	for _, path := range discs {
		resp, err := client.Get(ctx, target.EffectiveURL+path)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		got := fmt.Sprintf("%x", md5.Sum(resp.Body))
		switch got {
		case mv[path]:
			vMatch++
			if len(evidence) < 2 {
				evidence = append(evidence, fmt.Sprintf("%s md5=%s matches %s", path, got[:12], v))
			}
		case mp[path]:
			pMatch++
		}
	}
	return vMatch >= 1 && vMatch > pMatch, evidence
}

// wpStableVersions fetches the version->status map once per process.
func wpStableVersions(ctx context.Context) map[string]string {
	stableOnce.Do(func() {
		body, err := wpAPIGet(ctx, wpAPIBase+"/core/stable-check/1.0/")
		if err != nil {
			return
		}
		var m map[string]string
		if json.Unmarshal(body, &m) == nil {
			stableMap = m
		}
	})
	return stableMap
}

// wpChecksums fetches (and disk-caches) the file->md5 manifest for a release.
func wpChecksums(ctx context.Context, version string) map[string]string {
	if !validVersion(version) {
		return nil
	}
	if m, ok := manifestCache[version]; ok {
		return m
	}

	cachePath := checksumsCachePath(version)
	if cachePath != "" {
		if d, err := os.ReadFile(cachePath); err == nil && len(d) > 2 {
			var m map[string]string
			if json.Unmarshal(d, &m) == nil && len(m) > 0 {
				manifestCache[version] = m
				return m
			}
		}
	}

	body, err := wpAPIGet(ctx, fmt.Sprintf("%s/core/checksums/1.0/?version=%s&locale=en_US", wpAPIBase, version))
	if err != nil {
		return nil
	}
	var wrap struct {
		Checksums map[string]string `json:"checksums"`
	}
	if json.Unmarshal(body, &wrap) != nil || len(wrap.Checksums) == 0 {
		return nil
	}
	manifestCache[version] = wrap.Checksums
	if cachePath != "" {
		if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err == nil {
			if d, err := json.Marshal(wrap.Checksums); err == nil {
				_ = os.WriteFile(cachePath, d, 0644)
			}
		}
	}
	return wrap.Checksums
}

// wpAPIGet fetches from api.wordpress.org with a neutral client - deliberately
// not the scan's client, so the target's cookies/custom headers/UA are never
// sent to wordpress.org.
func wpAPIGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ghostpress")
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api.wordpress.org returned HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
}

func checksumsCachePath(version string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ghostpress", "checksums", version+".json")
}

// recentReleases returns up to n real releases at or below "latest", newest first.
func recentReleases(stable map[string]string, n int) []string {
	var all []string
	for v := range stable {
		all = append(all, v)
	}
	sortVersionsDesc(all)
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func predecessor(stable map[string]string, v string) string {
	best := ""
	for k := range stable {
		if model.CompareVersions(k, v) < 0 {
			if best == "" || model.CompareVersions(k, best) > 0 {
				best = k
			}
		}
	}
	return best
}

func sortVersionsDesc(vs []string) {
	sort.Slice(vs, func(i, j int) bool {
		return model.CompareVersions(vs[i], vs[j]) > 0
	})
}

func validVersion(v string) bool {
	if v == "" || len(v) > 16 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
