package wp

import (
	"strings"
	"testing"
)

// Regression test for the loose [^/]+ slug capture that turned JSON/JS fragments
// (e.g. on a Cloudflare challenge page) into bogus plugin "slugs" like `*","`.
func TestPassivePluginFindersRejectsJunkSlugs(t *testing.T) {
	body := `
<link rel="stylesheet" href="https://example.com/wp-content/plugins/popup-maker/assets/css/site.css">
<script>var paths=["\/wp-content\/plugins\/*",".foo"];</script>
<a href="/wp-content/plugins/*","/x/">junk</a>
<img src="/wp-content/plugins/contact-form-7/img/logo.png">
`
	tgt := &Target{Homepage: []byte(body), ContentDir: "wp-content"}

	slugs := map[string]bool{}
	for _, p := range passivePluginFinders(tgt) {
		slugs[p.Slug] = true
	}

	if !slugs["popup-maker"] {
		t.Errorf("expected real slug popup-maker, got %v", slugs)
	}
	if !slugs["contact-form-7"] {
		t.Errorf("expected real slug contact-form-7, got %v", slugs)
	}
	for s := range slugs {
		if strings.ContainsAny(s, `*",'`) {
			t.Errorf("junk slug captured: %q", s)
		}
	}
}
