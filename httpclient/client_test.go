package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestRetryOn429(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.Header().Set("Retry-After", "0") // keep the test fast
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, _ := New(Options{Threads: 2})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 after retries, got %d", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Fatalf("expected 3 attempts (2 retries), got %d", n)
	}
	if rl, _ := c.Interference(); rl != 2 {
		t.Fatalf("expected 2 rate-limited responses recorded, got %d", rl)
	}
}

func TestForbiddenCountedNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, _ := New(Options{Threads: 1})
	resp, _ := c.Get(context.Background(), srv.URL)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("403 must not be retried; got %d calls", n)
	}
	if _, fb := c.Interference(); fb != 1 {
		t.Fatalf("expected 1 forbidden recorded, got %d", fb)
	}
}
