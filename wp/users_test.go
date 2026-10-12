package wp

import "testing"

// The author-class heuristic must only read the <body> tag's class list, so
// generic component classes elsewhere on the page are not mistaken for users.
func TestPassiveUserFindersBodyClassScope(t *testing.T) {
	body := `
<body class="home blog wp-custom-logo">
  <div class="author-box"><span class="author-name">Jane Doe</span></div>
  <a href="/author/jane-doe/">Jane</a>
</body>`
	tgt := &Target{Homepage: []byte(body), ContentDir: "wp-content"}

	names := map[string]bool{}
	for _, u := range passiveUserFinders(tgt) {
		names[u.Username] = true
	}
	// Real author link slug is legitimate; CSS component classes must not leak.
	if !names["jane-doe"] {
		t.Errorf("expected author link slug jane-doe, got %v", names)
	}
	for _, junk := range []string{"box", "name", "avatar", "meta"} {
		if names[junk] {
			t.Errorf("component class leaked as username: %q (%v)", junk, names)
		}
	}
}

func TestPassiveUserFindersBodyAuthorClass(t *testing.T) {
	// On an author archive page WordPress stamps author-<nicename> on <body>.
	body := `<body class="archive author author-jsmith author-7">content</body>`
	tgt := &Target{Homepage: []byte(body), ContentDir: "wp-content"}

	names := map[string]bool{}
	for _, u := range passiveUserFinders(tgt) {
		names[u.Username] = true
	}
	if !names["jsmith"] {
		t.Errorf("expected jsmith from body author class, got %v", names)
	}
	if names["7"] {
		t.Errorf("numeric author-<id> must not be treated as a username: %v", names)
	}
}
