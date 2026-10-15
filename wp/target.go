package wp

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"ghostpress/httpclient"
)

// slugCharClass matches a valid WordPress plugin/theme directory slug: it must
// start alphanumeric and contain only slug-safe characters. Using this instead
// of a loose [^/]+ prevents JSON/JS fragments on a page (or a Cloudflare
// challenge page) from being captured as bogus slugs like `*","`.
const slugCharClass = `[a-zA-Z0-9][a-zA-Z0-9._-]*`

type Target struct {
	URL             string
	EffectiveURL    string
	IP              string
	Server          string
	Homepage        []byte
	HomepageHeaders http.Header
	NotFoundBody    []byte
	ContentDir      string
	PluginsDir      string
	SubDir          string
	IsWordPress     bool
	WPVersion       string // detected core version, used to discard default ?ver= values
}

func NewTarget(ctx context.Context, client *httpclient.Client, rawURL string, force bool) (*Target, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	if !strings.HasSuffix(rawURL, "/") {
		rawURL += "/"
	}

	t := &Target{
		URL:        rawURL,
		ContentDir: "wp-content",
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	ips, err := net.LookupHost(parsed.Hostname())
	if err == nil && len(ips) > 0 {
		t.IP = ips[0]
	}

	resp, err := client.Get(ctx, rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch homepage: %w", err)
	}

	t.EffectiveURL = resp.URL
	t.Homepage = resp.Body
	t.HomepageHeaders = resp.Headers
	t.Server = resp.Headers.Get("Server")

	t.detectContentDir()
	t.PluginsDir = t.ContentDir + "/plugins"

	t.IsWordPress = t.detectWordPress(resp)
	if !t.IsWordPress && !force {
		return t, nil
	}

	notFoundURL := rawURL + fmt.Sprintf("%x", md5.Sum([]byte("ghostpress-404-check")))
	nfResp, err := client.Get(ctx, notFoundURL)
	if err == nil {
		t.NotFoundBody = nfResp.Body
	}

	return t, nil
}

func (t *Target) detectWordPress(resp *httpclient.Response) bool {
	body := string(resp.Body)

	wpPatterns := []string{
		"/wp-content/",
		"/wp-includes/",
		"wp-admin",
		`<meta name="generator" content="WordPress`,
	}
	for _, p := range wpPatterns {
		if strings.Contains(body, p) {
			return true
		}
	}

	if resp.Headers.Get("X-Pingback") != "" && strings.Contains(resp.Headers.Get("X-Pingback"), "xmlrpc.php") {
		return true
	}

	linkHeader := resp.Headers.Get("Link")
	if strings.Contains(linkHeader, "wp-json") {
		return true
	}

	return false
}

var contentDirRe = regexp.MustCompile(`(?i)(https?://[^/"'\s]+)?/([a-z0-9][a-z0-9._-]*)/(?:plugins|themes)/`)

// detectContentDir infers the wp-content directory name (it is often renamed,
// e.g. "app" on Bedrock sites). It must ignore third-party URLs in the markup:
// Yoast SEO, for one, stamps a literal https://yoast.com/wordpress/plugins/seo/
// link into every page's <head>, and naively taking the first /<dir>/plugins/
// match there yields "wordpress", which breaks all plugin/theme probing. So we
// only count matches that are site-relative or on the target's own host, and
// pick the most frequent directory (the real content dir dominates by count).
func (t *Target) detectContentDir() {
	body := string(t.Homepage)

	host := ""
	if u, err := url.Parse(t.EffectiveURL); err == nil {
		host = u.Hostname()
	}

	counts := make(map[string]int)
	for _, m := range contentDirRe.FindAllStringSubmatch(body, -1) {
		if m[1] != "" { // absolute URL - only trust it if it's the target's own host
			hu, err := url.Parse(m[1])
			if err != nil || !sameHost(hu.Hostname(), host) {
				continue
			}
		}
		counts[strings.ToLower(m[2])]++
	}

	best, bestN := "", 0
	for dir, n := range counts {
		if n > bestN {
			best, bestN = dir, n
		}
	}
	if best != "" {
		t.ContentDir = best
	}
}

// sameHost compares two hostnames, treating a leading "www." as equivalent.
func sameHost(a, b string) bool {
	a = strings.TrimPrefix(strings.ToLower(a), "www.")
	b = strings.TrimPrefix(strings.ToLower(b), "www.")
	return a != "" && a == b
}

func (t *Target) PluginURL(slug string) string {
	return t.EffectiveURL + t.PluginsDir + "/" + slug + "/"
}

func (t *Target) ThemeURL(slug string) string {
	return t.EffectiveURL + t.ContentDir + "/themes/" + slug + "/"
}

func (t *Target) LoginURL(loginURI string) string {
	if loginURI != "" {
		return t.EffectiveURL + strings.TrimPrefix(loginURI, "/")
	}
	return t.EffectiveURL + "wp-login.php"
}

func (t *Target) XMLRPCURL() string {
	return t.EffectiveURL + "xmlrpc.php"
}

func (t *Target) IsNotFoundBody(body []byte) bool {
	if len(t.NotFoundBody) == 0 {
		return false
	}
	return string(body) == string(t.NotFoundBody)
}

func (t *Target) IsSoft404(resp *httpclient.Response) bool {
	if resp.StatusCode != 200 {
		return false
	}

	body := string(resp.Body)

	if strings.Contains(body, "error404") ||
		strings.Contains(body, "Error 404") ||
		strings.Contains(body, "page-not-found") {
		return true
	}

	if len(t.NotFoundBody) > 0 && len(resp.Body) > 0 {
		ratio := float64(len(resp.Body)) / float64(len(t.NotFoundBody))
		if ratio > 0.95 && ratio < 1.05 {
			return true
		}
	}

	return false
}
