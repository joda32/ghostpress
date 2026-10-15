package wp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"ghostpress/httpclient"
)

// The aggressive plugin finder must HEAD-probe first and only GET the few
// candidates that respond, so a missing plugin's large 404 body is never
// downloaded. This locks in that behavior (the fix for multi-MB scans).
func TestAggressivePluginFindersHeadFirst(t *testing.T) {
	bigBody := strings.Repeat("x", 200*1024)

	var mu sync.Mutex
	methods := map[string]string{} // path -> last method seen

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods[r.URL.Path] = r.Method
		mu.Unlock()

		switch {
		case r.URL.Path == "/wp-content/plugins/akismet/":
			w.WriteHeader(http.StatusForbidden) // present, listing denied
		case strings.HasSuffix(r.URL.Path, "/jetpack/readme.txt"):
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				w.Write([]byte("=== Jetpack ===\nStable tag: 1.2.3\n"))
			}
		default:
			// Everything else is a 404 with a large error-page body that must
			// only ever be returned to a GET (and HEAD-first means never here).
			w.WriteHeader(http.StatusNotFound)
			if r.Method == http.MethodGet {
				w.Write([]byte(bigBody))
			}
		}
	}))
	defer srv.Close()

	client, _ := httpclient.New(httpclient.Options{Threads: 4})
	target := &Target{
		EffectiveURL: srv.URL + "/",
		ContentDir:   "wp-content",
		PluginsDir:   "wp-content/plugins",
	}

	got := map[string]bool{}
	for _, p := range aggressivePluginFinders(context.Background(), client, target, []string{"akismet", "jetpack", "missing1", "missing2"}) {
		got[p.Slug] = true
	}

	if !got["akismet"] {
		t.Error("akismet (dir 403) should be found")
	}
	if !got["jetpack"] {
		t.Error("jetpack (readme.txt) should be found")
	}
	if got["missing1"] || got["missing2"] {
		t.Errorf("missing plugins must not be reported: %v", got)
	}

	// The crucial assertion: a missing plugin's dir was only HEAD-probed, never
	// GET-ed, so its 200 KB 404 body was not downloaded.
	mu.Lock()
	defer mu.Unlock()
	if m := methods["/wp-content/plugins/missing1/"]; m != "HEAD" {
		t.Errorf("missing plugin dir should be probed with HEAD only, got %q", m)
	}
}
