package wp

import "testing"

// Yoast SEO stamps a literal https://yoast.com/wordpress/plugins/seo/ link into
// every page. detectContentDir must not latch onto that third-party URL and
// mis-detect the content dir as "wordpress" (which breaks all plugin probing).
func TestDetectContentDirIgnoresThirdPartyYoastURL(t *testing.T) {
	body := `<head>
<!-- This site is optimized with the Yoast SEO plugin - https://yoast.com/wordpress/plugins/seo/ -->
<link rel="stylesheet" href="https://www.example.com/wp-content/plugins/elementor/style.css">
<script src="/wp-content/themes/hello/main.js"></script>
</head>`
	tgt := &Target{EffectiveURL: "https://www.example.com/", Homepage: []byte(body), ContentDir: "wp-content"}
	tgt.detectContentDir()
	if tgt.ContentDir != "wp-content" {
		t.Errorf("content dir should stay wp-content (ignoring yoast.com URL), got %q", tgt.ContentDir)
	}
}

// A genuinely renamed content dir on the target's own host must be picked up.
func TestDetectContentDirRenamed(t *testing.T) {
	body := `<link href="https://www.example.com/app/plugins/acf/x.css">
<script src="/app/themes/base/main.js"></script>
<img src="/app/plugins/foo/a.png">`
	tgt := &Target{EffectiveURL: "https://www.example.com/", Homepage: []byte(body), ContentDir: "wp-content"}
	tgt.detectContentDir()
	if tgt.ContentDir != "app" {
		t.Errorf("want renamed content dir app, got %q", tgt.ContentDir)
	}
}

// Site-relative paths (no host) are trusted, and the most frequent dir wins over
// a single stray third-party match.
func TestDetectContentDirPrefersMostFrequentOwnHost(t *testing.T) {
	body := `<!-- https://yoast.com/wordpress/plugins/seo/ -->
<link href="/wp-content/plugins/a/a.css">
<link href="/wp-content/plugins/b/b.css">
<link href="/wp-content/themes/t/t.css">`
	tgt := &Target{EffectiveURL: "https://blog.example.com/", Homepage: []byte(body), ContentDir: "wp-content"}
	tgt.detectContentDir()
	if tgt.ContentDir != "wp-content" {
		t.Errorf("want wp-content, got %q", tgt.ContentDir)
	}
}
