package wp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ghostpress/httpclient"
)

func TestModalVersion(t *testing.T) {
	// plurality wins
	if v, n := modalVersion(map[string]int{"7.1.4": 5, "7.1.1": 1}); v != "7.1.4" || n != 5 {
		t.Fatalf("plurality: got %q x%d, want 7.1.4 x5", v, n)
	}
	// ties break toward the highest version, deterministically
	if v, _ := modalVersion(map[string]int{"7.1.1": 2, "7.1.3": 2, "7.1.2": 2}); v != "7.1.3" {
		t.Fatalf("tie: got %q, want highest 7.1.3", v)
	}
}

func TestIntersectVersionSets(t *testing.T) {
	sets := [][]string{
		{"7.1.1", "7.1.2", "7.1.3"},
		{"7.1", "7.1.1", "7.1.2", "7.1.3"},
		{"6.4", "7.0", "7.1.1", "7.1.2", "7.1.3"},
	}
	got := intersectVersionSets(sets)
	sortVersionsAsc(got)
	want := []string{"7.1.1", "7.1.2", "7.1.3"}
	if len(got) != len(want) {
		t.Fatalf("intersection size: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("intersection: got %v, want %v", got, want)
		}
	}

	// A disjoint set yields the empty intersection (caller falls back to votes).
	if g := intersectVersionSets([][]string{{"6.4"}, {"7.1.3"}}); len(g) != 0 {
		t.Fatalf("disjoint: want empty, got %v", g)
	}
}

// loginAssetVersion must read the WordPress core version off wp-login.php's
// wp-admin asset stamps and ignore a bundled plugin/library stamp - the real
// signal that pins 7.1.4 even when the fingerprint DB tops out at 7.1.3.
func TestLoginAssetVersion(t *testing.T) {
	login := `<!doctype html><html><head>
<link rel="stylesheet" href="https://x.test/wp-admin/css/login.min.css?ver=7.1.4">
<link rel="stylesheet" href="/wp-admin/css/forms.min.css?ver=7.1.4">
<link rel="stylesheet" href="/wp-admin/css/l10n.min.css?ver=7.1.4">
<script src="/wp-admin/js/password-strength-meter.min.js?ver=7.1.4"></script>
<script src="/wp-content/plugins/some-plugin/js/app.js?ver=1.2.3"></script>
</head><body></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-login.php" {
			w.WriteHeader(200)
			w.Write([]byte(login))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	client, _ := httpclient.New(httpclient.Options{Threads: 2})
	tgt := &Target{EffectiveURL: srv.URL + "/"}

	v := loginAssetVersion(context.Background(), client, tgt)
	if v == nil {
		t.Fatal("expected a version from login assets, got nil")
	}
	if v.Number != "7.1.4" {
		t.Fatalf("login version: got %q, want 7.1.4 (plugin stamp 1.2.3 must be ignored)", v.Number)
	}
	if v.Confidence < 85 {
		t.Fatalf("login confidence too low: %d", v.Confidence)
	}
}

func TestLoginAssetVersionAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	client, _ := httpclient.New(httpclient.Options{Threads: 2})
	tgt := &Target{EffectiveURL: srv.URL + "/"}
	if v := loginAssetVersion(context.Background(), client, tgt); v != nil {
		t.Fatalf("no wp-login.php: want nil, got %+v", v)
	}
}
