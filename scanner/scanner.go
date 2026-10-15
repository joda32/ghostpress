package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ghostpress/data"
	"ghostpress/httpclient"
	"ghostpress/model"
	"ghostpress/output"
	"ghostpress/wp"
)

type Scanner struct {
	client *httpclient.Client
	opts   model.ScanOptions
	out    output.Formatter
}

func New(opts model.ScanOptions, out output.Formatter) (*Scanner, error) {
	clientOpts := httpclient.Options{
		Threads:          opts.Threads,
		ThrottleMillis:   opts.ThrottleMillis,
		UserAgent:        opts.UserAgent,
		RandomUserAgent:  opts.RandomUserAgent,
		UserAgents:       data.UserAgents(),
		Proxy:            opts.Proxy,
		ProxyAuth:        opts.ProxyAuth,
		CookieString:     opts.CookieString,
		CustomHeaders:    opts.Headers,
		HTTPAuth:         opts.HTTPAuth,
		ConnectTimeout:   opts.ConnectTimeout,
		RequestTimeout:   opts.RequestTimeout,
		MaxRedirects:     opts.MaxRedirects,
		DisableTLSChecks: opts.DisableTLSChecks,
		Debug:            opts.Debug,
	}

	wp.SetDebug(opts.Debug)

	client, err := httpclient.New(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &Scanner{
		client: client,
		opts:   opts,
		out:    out,
	}, nil
}

func (s *Scanner) Run(ctx context.Context) *model.ScanResult {
	result := &model.ScanResult{
		StartTime: time.Now(),
	}

	s.out.Banner()

	target, err := wp.NewTarget(ctx, s.client, s.opts.URL, s.opts.Force)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to connect to target: %s", err)
		// Only certificate-*verification* failures are cured by --disable-tls-checks
		// (it sets InsecureSkipVerify). Other TLS handshake alerts - e.g.
		// "tls: unrecognized name" (server has no vhost/cert for this SNI) - are
		// server-side and that flag won't help, so don't suggest it misleadingly.
		if es := err.Error(); strings.Contains(es, "x509") || strings.Contains(es, "certificate") {
			result.Error += "\n  hint: the target's TLS certificate failed verification - re-run with --disable-tls-checks to scan anyway"
		}
		s.out.Error(result.Error)
		result.EndTime = time.Now()
		return result
	}

	result.Target = model.TargetInfo{
		URL:            target.URL,
		EffectiveURL:   target.EffectiveURL,
		IP:             target.IP,
		Server:         target.Server,
		WordPressFound: target.IsWordPress,
		ContentDir:     target.ContentDir,
		PluginsDir:     target.PluginsDir,
	}

	s.out.ScanStarted(result.Target)

	if !target.IsWordPress && !s.opts.Force {
		result.Error = "Target does not appear to be running WordPress"
		result.EndTime = time.Now()
		stats := s.client.GetStats()
		result.RequestsDone = int(stats.RequestsDone)
		result.DataReceived = stats.DataReceived
		rl, fb := s.client.Interference()
		result.RateLimited, result.Forbidden = int(rl), int(fb)
		s.out.ScanFinished(result)
		return result
	}

	mode := s.opts.DetectionMode
	if s.opts.Stealthy {
		mode = model.ModePassive
	}

	findings := wp.FindInteresting(ctx, s.client, target, mode)
	result.InterestingFindings = findings
	s.out.InterestingFindings(findings)

	version := wp.DetectVersion(ctx, s.client, target, mode)
	result.Version = version
	if version != nil {
		target.WPVersion = version.Number
	}
	s.out.Version(version)

	mainTheme := wp.DetectMainTheme(ctx, s.client, target, mode)
	result.MainTheme = mainTheme
	s.out.MainTheme(mainTheme)

	if s.opts.Enumerate.Any() {
		s.runEnumeration(ctx, target, mode, result)
	}

	if s.opts.Passwords != "" && len(result.Users) > 0 {
		pwResults := wp.RunPasswordAttack(ctx, s.client, target, result.Users, s.opts)
		result.PasswordResults = pwResults
		s.out.PasswordResults(pwResults)
	}

	result.EndTime = time.Now()
	stats := s.client.GetStats()
	result.RequestsDone = int(stats.RequestsDone)
	result.DataSent = stats.DataSent
	result.DataReceived = stats.DataReceived
	rl, fb := s.client.Interference()
	result.RateLimited, result.Forbidden = int(rl), int(fb)

	s.out.ScanFinished(result)
	return result
}

func (s *Scanner) runEnumeration(ctx context.Context, target *wp.Target, mode model.DetectionMode, result *model.ScanResult) {
	enumOpts := s.opts.Enumerate

	if enumOpts.Plugins || enumOpts.VulnerablePlugins || enumOpts.AllPlugins {
		plugins := wp.EnumeratePlugins(ctx, s.client, target, mode, s.opts.PluginsSlugs)
		result.Plugins = plugins
		s.out.Plugins(plugins)
	}

	if enumOpts.Themes || enumOpts.VulnerableThemes || enumOpts.AllThemes {
		themes := wp.EnumerateThemes(ctx, s.client, target, mode, result.MainTheme, s.opts.ThemesSlugs)
		result.Themes = themes
		s.out.Themes(themes)
	}

	if enumOpts.Users {
		users := wp.EnumerateUsers(ctx, s.client, target, mode, s.opts.UsersRange)
		result.Users = users
		s.out.Users(users)
	}

	if enumOpts.ConfigBackups {
		backups := wp.CheckConfigBackups(ctx, s.client, target, data.ConfigBackups())
		result.ConfigBackups = backups
		s.out.ConfigBackups(backups)
	}

	if enumOpts.DBExports {
		exports := wp.CheckDBExports(ctx, s.client, target, data.DBExports())
		result.DBExports = exports
		s.out.DBExports(exports)
	}

	if enumOpts.TimThumbs {
		timthumbs := wp.CheckTimThumbs(ctx, s.client, target, data.TimThumbs())
		result.TimThumbs = timthumbs
		s.out.TimThumbs(timthumbs)
	}

	if enumOpts.Medias {
		media := wp.EnumerateMedia(ctx, s.client, target, mode, s.opts.MediaRange)
		result.Media = media
		s.out.Media(media)
	}
}
