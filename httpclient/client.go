package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	URL        string
}

type Stats struct {
	RequestsDone int64
	DataSent     int64
	DataReceived int64
}

type Options struct {
	Threads          int
	ThrottleMillis   int
	UserAgent        string
	RandomUserAgent  bool
	UserAgents       []string
	Proxy            string
	ProxyAuth        string
	CookieString     string
	CustomHeaders    map[string]string
	HTTPAuth         string
	ConnectTimeout   int
	RequestTimeout   int
	MaxRedirects     int
	DisableTLSChecks bool
	Debug            bool
}

type Client struct {
	http         *http.Client
	sem          chan struct{}
	throttle     time.Duration
	userAgent    string
	randomUA     bool
	agents       []string
	headers      map[string]string
	httpAuth     string
	cookieString string
	debug        bool
	stats        Stats
	rateLimited  int64 // count of 429/503 responses seen (WAF interference)
	forbidden    int64 // count of 403 responses seen
	mu           sync.Mutex
}

const maxRetries = 3

// retryDelay computes how long to wait before retrying a rate-limited request,
// honouring a Retry-After header (seconds or HTTP date) and otherwise using
// capped exponential backoff.
func retryDelay(retryAfter string, attempt int) time.Duration {
	const cap = 30 * time.Second
	if retryAfter = strings.TrimSpace(retryAfter); retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs >= 0 {
			if d := time.Duration(secs) * time.Second; d <= cap {
				return d
			}
			return cap
		}
		if t, err := http.ParseTime(retryAfter); err == nil {
			if d := time.Until(t); d > 0 {
				if d > cap {
					return cap
				}
				return d
			}
		}
	}
	d := time.Duration(1<<attempt) * time.Second // 1s, 2s, 4s, ...
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}

// sleepCtx waits for d or until ctx is cancelled; returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Interference returns how many responses indicated WAF/rate-limit interference
// (429/503) or access denial (403) during the scan.
func (c *Client) Interference() (rateLimited, forbidden int64) {
	return atomic.LoadInt64(&c.rateLimited), atomic.LoadInt64(&c.forbidden)
}

func New(opts Options) (*Client, error) {
	if opts.Threads <= 0 {
		opts.Threads = 5
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 10
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 30
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "ghostpress"
	}

	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.DisableTLSChecks,
		},
		DialContext: (&net.Dialer{
			Timeout: time.Duration(opts.ConnectTimeout) * time.Second,
		}).DialContext,
		MaxIdleConns:        opts.Threads * 2,
		MaxIdleConnsPerHost: opts.Threads * 2,
		IdleConnTimeout:     90 * time.Second,
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		if opts.ProxyAuth != "" {
			parts := strings.SplitN(opts.ProxyAuth, ":", 2)
			if len(parts) == 2 {
				proxyURL.User = url.UserPassword(parts[0], parts[1])
			}
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	redirectCount := opts.MaxRedirects
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.RequestTimeout) * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= redirectCount {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	c := &Client{
		http:         httpClient,
		sem:          make(chan struct{}, opts.Threads),
		throttle:     time.Duration(opts.ThrottleMillis) * time.Millisecond,
		userAgent:    opts.UserAgent,
		randomUA:     opts.RandomUserAgent,
		agents:       opts.UserAgents,
		headers:      opts.CustomHeaders,
		httpAuth:     opts.HTTPAuth,
		cookieString: opts.CookieString,
		debug:        opts.Debug,
	}

	return c, nil
}

// defaultMaxBody bounds how much of a response body is buffered when no explicit
// cap is given. Callers probing for existence/version pass a much smaller cap via
// the *Capped helpers so large soft-404 / error pages aren't read in full.
const defaultMaxBody = 10 * 1024 * 1024

func (c *Client) do(ctx context.Context, method, rawURL string, body io.Reader, contentType string, maxBody int64) (*Response, error) {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}

	// Buffer the body so the request can be rebuilt on retry.
	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = io.ReadAll(body)
	}

	for attempt := 0; ; attempt++ {
		if c.throttle > 0 {
			time.Sleep(c.throttle)
		}

		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
		if err != nil {
			return nil, err
		}

		if c.randomUA && len(c.agents) > 0 {
			req.Header.Set("User-Agent", c.agents[rand.Intn(len(c.agents))])
		} else {
			req.Header.Set("User-Agent", c.userAgent)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		if c.cookieString != "" {
			req.Header.Set("Cookie", c.cookieString)
		}
		if c.httpAuth != "" {
			parts := strings.SplitN(c.httpAuth, ":", 2)
			if len(parts) == 2 {
				req.SetBasicAuth(parts[0], parts[1])
			}
		}

		start := time.Now()
		resp, err := c.http.Do(req)
		if err != nil {
			c.dbg(method, rawURL, 0, 0, time.Since(start), err)
			return nil, err
		}

		respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if rerr != nil {
			c.dbg(method, rawURL, resp.StatusCode, len(respBody), time.Since(start), rerr)
			return nil, rerr
		}

		atomic.AddInt64(&c.stats.RequestsDone, 1)
		atomic.AddInt64(&c.stats.DataReceived, int64(len(respBody)))
		c.dbg(method, rawURL, resp.StatusCode, len(respBody), time.Since(start), nil)

		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			atomic.AddInt64(&c.rateLimited, 1)
			if attempt < maxRetries {
				delay := retryDelay(resp.Header.Get("Retry-After"), attempt)
				c.dbg(method, rawURL, resp.StatusCode, 0, 0, fmt.Errorf("rate-limited, backing off %v (retry %d/%d)", delay, attempt+1, maxRetries))
				if !sleepCtx(ctx, delay) {
					return c.respFrom(resp, respBody, rawURL), nil
				}
				continue
			}
		case http.StatusForbidden:
			atomic.AddInt64(&c.forbidden, 1)
		}

		return c.respFrom(resp, respBody, rawURL), nil
	}
}

func (c *Client) respFrom(resp *http.Response, body []byte, rawURL string) *Response {
	u := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		u = resp.Request.URL.String()
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		URL:        u,
	}
}

// dbg logs one request to stderr when debug mode is on.
func (c *Client) dbg(method, url string, status, n int, dur time.Duration, err error) {
	if !c.debug {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[debug] %-4s ERR  %-55s (%v) %v\n", method, url, dur.Round(time.Millisecond), err)
		return
	}
	fmt.Fprintf(os.Stderr, "[debug] %-4s %3d %7dB  %-55s (%v)\n", method, status, n, url, dur.Round(time.Millisecond))
}

func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.do(ctx, http.MethodGet, url, nil, "", 0)
}

// GetCapped is Get but buffers at most maxBody bytes of the response. Use it for
// existence/version probes where only a small prefix is inspected, so a large
// soft-404 or error page isn't read in full.
func (c *Client) GetCapped(ctx context.Context, url string, maxBody int64) (*Response, error) {
	return c.do(ctx, http.MethodGet, url, nil, "", maxBody)
}

func (c *Client) Head(ctx context.Context, url string) (*Response, error) {
	return c.do(ctx, http.MethodHead, url, nil, "", 0)
}

func (c *Client) Post(ctx context.Context, url string, contentType string, body []byte) (*Response, error) {
	return c.do(ctx, http.MethodPost, url, strings.NewReader(string(body)), contentType, 0)
}

func (c *Client) PostWithCookie(ctx context.Context, rawURL string, contentType string, body []byte, cookie string) (*Response, error) {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	if c.throttle > 0 {
		time.Sleep(c.throttle)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	if c.randomUA && len(c.agents) > 0 {
		req.Header.Set("User-Agent", c.agents[rand.Intn(len(c.agents))])
	} else {
		req.Header.Set("User-Agent", c.userAgent)
	}

	req.Header.Set("Content-Type", contentType)
	cookies := cookie
	if c.cookieString != "" {
		if cookies != "" {
			cookies = c.cookieString + "; " + cookies
		} else {
			cookies = c.cookieString
		}
	}
	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	if c.httpAuth != "" {
		parts := strings.SplitN(c.httpAuth, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}

	noRedirectClient := *c.http
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	start := time.Now()
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		c.dbg(http.MethodPost, rawURL, 0, 0, time.Since(start), err)
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		c.dbg(http.MethodPost, rawURL, resp.StatusCode, len(respBody), time.Since(start), err)
		return nil, err
	}

	atomic.AddInt64(&c.stats.RequestsDone, 1)
	atomic.AddInt64(&c.stats.DataReceived, int64(len(respBody)))
	c.dbg(http.MethodPost, rawURL, resp.StatusCode, len(respBody), time.Since(start), nil)

	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		atomic.AddInt64(&c.rateLimited, 1)
	case http.StatusForbidden:
		atomic.AddInt64(&c.forbidden, 1)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		URL:        rawURL,
	}, nil
}

func (c *Client) GetStats() Stats {
	return Stats{
		RequestsDone: atomic.LoadInt64(&c.stats.RequestsDone),
		DataSent:     atomic.LoadInt64(&c.stats.DataSent),
		DataReceived: atomic.LoadInt64(&c.stats.DataReceived),
	}
}

type BulkResult struct {
	URL      string
	Response *Response
	Error    error
}

func (c *Client) BulkHead(ctx context.Context, urls []string) []BulkResult {
	return c.bulk(ctx, http.MethodHead, urls, 0)
}

func (c *Client) BulkGet(ctx context.Context, urls []string) []BulkResult {
	return c.bulk(ctx, http.MethodGet, urls, 0)
}

// BulkGetCapped is BulkGet but buffers at most maxBody bytes of each response.
func (c *Client) BulkGetCapped(ctx context.Context, urls []string, maxBody int64) []BulkResult {
	return c.bulk(ctx, http.MethodGet, urls, maxBody)
}

func (c *Client) bulk(ctx context.Context, method string, urls []string, maxBody int64) []BulkResult {
	results := make([]BulkResult, len(urls))
	var wg sync.WaitGroup

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, rawURL string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				results[idx] = BulkResult{URL: rawURL, Error: ctx.Err()}
				return
			default:
			}

			resp, err := c.do(ctx, method, rawURL, nil, "", maxBody)
			results[idx] = BulkResult{URL: rawURL, Response: resp, Error: err}
		}(i, u)
	}

	wg.Wait()
	return results
}

func (c *Client) HeadOrGet(ctx context.Context, url string) (*Response, error) {
	resp, err := c.Head(ctx, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusBadRequest {
		return c.Get(ctx, url)
	}
	return resp, nil
}
