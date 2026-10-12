package wp

import (
	"net/http"
	"testing"

	"ghostpress/httpclient"
)

func TestVersionFromHomepageAssets(t *testing.T) {
	body := `
<link href="https://x.test/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.21.0" rel="stylesheet">
<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.21.0&foo=1"></script>
<link href="/wp-content/themes/hello-elementor/style.css?ver=2.8.1">
`
	tgt := &Target{Homepage: []byte(body), ContentDir: "wp-content"}

	if v := versionFromHomepageAssets(tgt, "plugins", "elementor"); v != "3.21.0" {
		t.Errorf("plugin elementor: want 3.21.0, got %q", v)
	}
	if v := versionFromHomepageAssets(tgt, "themes", "hello-elementor"); v != "2.8.1" {
		t.Errorf("theme hello-elementor: want 2.8.1, got %q", v)
	}
	if v := versionFromHomepageAssets(tgt, "plugins", "not-present"); v != "" {
		t.Errorf("absent plugin: want empty, got %q", v)
	}
}

func TestVersionFromHomepageAssetsExcludesCoreVersion(t *testing.T) {
	// simple-post-redirect's only asset is stamped with the WP core version
	// (WordPress default), which must be discarded -> no version recovered.
	body := `<script src="/wp-content/plugins/simple-post-redirect/js/app.js?ver=7.1.3"></script>`
	tgt := &Target{Homepage: []byte(body), ContentDir: "wp-content", WPVersion: "7.1.3"}
	if v := versionFromHomepageAssets(tgt, "plugins", "simple-post-redirect"); v != "" {
		t.Errorf("core-version ?ver should be discarded, got %q", v)
	}
}

func TestVersionFromHomepageAssetsPrefersMode(t *testing.T) {
	// elementor's own assets (3.21.0 ×2) outnumber a bundled library (5.43.0 ×1);
	// the most frequent value wins over the max.
	body := `
<link href="/wp-content/plugins/elementor/assets/css/frontend.css?ver=3.21.0">
<script src="/wp-content/plugins/elementor/assets/js/frontend.js?ver=3.21.0"></script>
<script src="/wp-content/plugins/elementor/lib/vendor/bundle.js?ver=5.43.0"></script>
`
	tgt := &Target{Homepage: []byte(body), ContentDir: "wp-content"}
	if v := versionFromHomepageAssets(tgt, "plugins", "elementor"); v != "3.21.0" {
		t.Errorf("mode should win over max: want 3.21.0, got %q", v)
	}
}

func TestNotRealFileSoft404(t *testing.T) {
	// A 200 response with an HTML content-type is a soft-404, not a readme.
	htmlResp := &httpclient.Response{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": []string{"text/html; charset=UTF-8"}},
		Body:       []byte("<html>not found</html>"),
	}
	tgt := &Target{}
	if !notRealFile(htmlResp, tgt) {
		t.Error("expected HTML 200 to be flagged as not-a-real-file")
	}

	plainResp := &httpclient.Response{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": []string{"text/plain"}},
		Body:       []byte("=== Popup Maker ===\nStable tag: 1.25.0\n"),
	}
	if notRealFile(plainResp, tgt) {
		t.Error("expected a text/plain readme to be accepted")
	}
	if v := stableTagVersion(plainResp); v != "1.25.0" {
		t.Errorf("stableTagVersion: want 1.25.0, got %q", v)
	}
}
