package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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
}

type Client struct {
	http       *http.Client
	sem        chan struct{}
	throttle   time.Duration
	userAgent  string
	randomUA   bool
	agents     []string
	headers      map[string]string
	httpAuth     string
	cookieString string
	stats        Stats
	mu           sync.Mutex
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
	}

	return c, nil
}

func (c *Client) do(ctx context.Context, method, rawURL string, body io.Reader, contentType string) (*Response, error) {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	if c.throttle > 0 {
		time.Sleep(c.throttle)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
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

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&c.stats.RequestsDone, 1)
	atomic.AddInt64(&c.stats.DataReceived, int64(len(respBody)))

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		URL:        resp.Request.URL.String(),
	}, nil
}

func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.do(ctx, http.MethodGet, url, nil, "")
}

func (c *Client) Head(ctx context.Context, url string) (*Response, error) {
	return c.do(ctx, http.MethodHead, url, nil, "")
}

func (c *Client) Post(ctx context.Context, url string, contentType string, body []byte) (*Response, error) {
	return c.do(ctx, http.MethodPost, url, strings.NewReader(string(body)), contentType)
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

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&c.stats.RequestsDone, 1)
	atomic.AddInt64(&c.stats.DataReceived, int64(len(respBody)))

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
	return c.bulk(ctx, http.MethodHead, urls)
}

func (c *Client) BulkGet(ctx context.Context, urls []string) []BulkResult {
	return c.bulk(ctx, http.MethodGet, urls)
}

func (c *Client) bulk(ctx context.Context, method string, urls []string) []BulkResult {
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

			resp, err := c.do(ctx, method, rawURL, nil, "")
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
