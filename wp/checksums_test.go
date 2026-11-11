package wp

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"ghostpress/httpclient"
)

func md5hex(s string) string { return fmt.Sprintf("%x", md5.Sum([]byte(s))) }

func TestVerifyExact(t *testing.T) {
	// Two releases whose two discriminating assets differ. The target serves the
	// 7.1.4 bytes, so verifyExact must confirm 7.1.4 over its predecessor 7.1.3.
	pathA := "wp-admin/js/common.min.js"
	pathB := "wp-includes/js/dist/block-library.min.js"
	v714A, v714B := "common-714", "block-714"
	v713A, v713B := "common-713", "block-713"

	manifestCache["7.1.4"] = map[string]string{pathA: md5hex(v714A), pathB: md5hex(v714B)}
	manifestCache["7.1.3"] = map[string]string{pathA: md5hex(v713A), pathB: md5hex(v713B)}
	defer func() { delete(manifestCache, "7.1.4"); delete(manifestCache, "7.1.3") }()

	serve := func(a, b string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/" + pathA:
				w.Write([]byte(a))
			case "/" + pathB:
				w.Write([]byte(b))
			default:
				w.WriteHeader(404)
			}
		}))
	}

	client, _ := httpclient.New(httpclient.Options{Threads: 2})

	// Target is genuinely 7.1.4.
	srv := serve(v714A, v714B)
	defer srv.Close()
	tgt := &Target{EffectiveURL: srv.URL + "/"}
	ok, ev := verifyExact(context.Background(), client, tgt, "7.1.4", "7.1.3")
	if !ok {
		t.Fatalf("expected 7.1.4 to verify, got false")
	}
	if len(ev) == 0 {
		t.Fatal("expected evidence naming the matched files")
	}

	// Target is actually 7.1.3 - verifying 7.1.4 must fail.
	srv2 := serve(v713A, v713B)
	defer srv2.Close()
	tgt2 := &Target{EffectiveURL: srv2.URL + "/"}
	if ok, _ := verifyExact(context.Background(), client, tgt2, "7.1.4", "7.1.3"); ok {
		t.Fatal("expected 7.1.4 verification to fail on a 7.1.3 target")
	}
}

func TestConfirmDisabledIsOffline(t *testing.T) {
	SetWPAPIEnabled(false)
	defer SetWPAPIEnabled(true)
	if v := confirmVersionViaChecksums(context.Background(), nil, &Target{}, "7.1.1"); v != nil {
		t.Fatalf("with the WP API disabled, confirmation must be a no-op, got %+v", v)
	}
}

func TestChecksumHelpers(t *testing.T) {
	stable := map[string]string{"7.1.4": "latest", "7.1.3": "outdated", "7.0.8": "outdated", "6.9.11": "outdated"}
	if p := predecessor(stable, "7.1.4"); p != "7.1.3" {
		t.Errorf("predecessor(7.1.4) = %q, want 7.1.3", p)
	}
	if p := predecessor(stable, "6.9.11"); p != "" {
		t.Errorf("predecessor of oldest should be empty, got %q", p)
	}
	rr := recentReleases(stable, 2)
	if len(rr) != 2 || rr[0] != "7.1.4" || rr[1] != "7.1.3" {
		t.Errorf("recentReleases newest-first = %v, want [7.1.4 7.1.3]", rr)
	}
	if !validVersion("7.1.4") || validVersion("7.1.4; rm -rf") || validVersion("") {
		t.Error("validVersion gate is wrong")
	}
}
