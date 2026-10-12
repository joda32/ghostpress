package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ghostpress/data"
	"ghostpress/model"
	"ghostpress/output"
	"ghostpress/scanner"

	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	vulnDBURL = ""
)

func main() {
	var opts model.ScanOptions
	var enumerate string

	rootCmd := &cobra.Command{
		Use:   "ghostpress [flags] URL",
		Short: "WordPress Security Auditor",
		Long:  "Ghostpress - A fast, portable WordPress security scanner written in Go.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.URL = args[0]
			return runScan(opts, enumerate)
		},
	}

	flags := rootCmd.Flags()

	flags.StringVar(&opts.OutputFormat, "format", "cli", "Output format (cli, json)")
	flags.StringVarP(&opts.OutputFile, "output", "o", "", "Output file (default: stdout)")
	flags.BoolVar(&opts.Force, "force", false, "Scan even if WordPress is not detected")
	flags.BoolVar(&opts.Stealthy, "stealthy", false, "Stealth mode (random UA + passive detection)")

	detectionMode := "mixed"
	flags.StringVar(&detectionMode, "detection-mode", "mixed", "Detection mode (passive, mixed, aggressive)")

	flags.IntVarP(&opts.Threads, "threads", "t", 5, "Number of concurrent threads")
	flags.IntVar(&opts.ThrottleMillis, "throttle", 0, "Milliseconds to wait between requests")
	flags.StringVar(&opts.UserAgent, "user-agent", "ghostpress/"+version, "User agent string")
	flags.BoolVar(&opts.RandomUserAgent, "random-user-agent", false, "Rotate user agents randomly")
	flags.StringVar(&opts.Proxy, "proxy", "", "Proxy URL (http://host:port or socks5://host:port)")
	flags.StringVar(&opts.ProxyAuth, "proxy-auth", "", "Proxy authentication (user:pass)")
	flags.StringVar(&opts.CookieString, "cookie-string", "", "Cookie string for requests")
	flags.StringVar(&opts.HTTPAuth, "http-auth", "", "HTTP basic auth (user:pass)")
	flags.IntVar(&opts.ConnectTimeout, "connect-timeout", 10, "Connection timeout in seconds")
	flags.IntVar(&opts.RequestTimeout, "request-timeout", 30, "Request timeout in seconds")
	flags.IntVar(&opts.MaxRedirects, "max-redirects", 10, "Maximum number of redirects")
	flags.BoolVar(&opts.DisableTLSChecks, "disable-tls-checks", false, "Disable TLS certificate verification")
	flags.BoolVarP(&opts.Debug, "debug", "v", false, "Verbose debug logging to stderr (per-request status + detection reasoning)")

	flags.StringVarP(&enumerate, "enumerate", "e", "", "Enumeration options (p,vp,ap,t,vt,at,u,cb,dbe,tt,m)")
	flags.StringVar(&opts.UsersRange, "users-range", "10", "User ID range for brute forcing (default: 10)")
	flags.StringVar(&opts.MediaRange, "media-range", "50", "Attachment ID range for media brute forcing (default: 50)")
	flags.StringVar(&opts.PluginsSlugs, "plugins-list", "", "File of plugin slugs to check (one per line; default: built-in popular list)")
	flags.StringVar(&opts.ThemesSlugs, "themes-list", "", "File of theme slugs to check (one per line; default: built-in popular list)")

	flags.StringVar(&opts.Passwords, "passwords", "", "Path to password wordlist file")
	flags.StringSliceVar(&opts.Usernames, "usernames", nil, "Usernames to attack (default: enumerated users)")
	flags.StringVar(&opts.PasswordAttack, "password-attack", "wp-login", "Password attack method (wp-login, xmlrpc, xmlrpc-multicall)")
	flags.StringVar(&opts.LoginURI, "login-uri", "", "Custom login URI")

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		opts.DetectionMode = model.ParseDetectionMode(detectionMode)
		if opts.Stealthy {
			opts.RandomUserAgent = true
			opts.DetectionMode = model.ModePassive
		}
		return nil
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ghostpress %s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	var updateURL string
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update the vulnerability database",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return updateVulnDB(updateURL)
		},
	}
	updateCmd.Flags().StringVar(&updateURL, "url", vulnDBURL, "URL to fetch vulndb.json from")
	rootCmd.AddCommand(updateCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(opts model.ScanOptions, enumerate string) error {
	parseEnumerate(enumerate, &opts.Enumerate)

	if !opts.Enumerate.Any() {
		opts.Enumerate.Plugins = true
		opts.Enumerate.Themes = true
		opts.Enumerate.Users = true
	}

	var outFile *os.File
	if opts.OutputFile != "" {
		f, err := os.Create(opts.OutputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		outFile = f
	}

	var formatter output.Formatter
	switch strings.ToLower(opts.OutputFormat) {
	case "json":
		formatter = output.NewJSON(outFile)
	default:
		noColor := outFile != nil
		formatter = output.NewCLI(noColor, outFile)
	}

	s, err := scanner.New(opts, formatter)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nInterrupted, shutting down...\n")
		cancel()
	}()

	result := s.Run(ctx)
	if result.Error != "" && !result.Target.WordPressFound {
		return fmt.Errorf("%s", result.Error)
	}

	if result.Vulnerable() {
		os.Exit(5)
	}

	return nil
}

func updateVulnDB(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("no update URL configured\n\nSet via:\n  --url flag\n  build with: -ldflags \"-X main.vulnDBURL=https://github.com/OWNER/ghostpress/releases/download/vulndb-latest/vulndb.json.gz\"")
	}

	fmt.Printf("[*] Downloading vulnerability database from:\n    %s\n", rawURL)

	client := &http.Client{Timeout: 60 * time.Second}

	body, err := fetchURL(client, rawURL)
	if err != nil {
		return err
	}

	// Best-effort integrity check against a sibling <url>.sha256.
	if sum, serr := fetchURL(client, rawURL+".sha256"); serr == nil {
		want := strings.ToLower(strings.Fields(string(sum))[0])
		got := fmt.Sprintf("%x", sha256.Sum256(body))
		if _, derr := hex.DecodeString(want); derr == nil && want != got {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", want, got)
		}
		fmt.Printf("[*] Checksum verified\n")
	}

	// The published artifact is gzip-compressed; store raw JSON locally.
	jsonBody := body
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		r, gerr := gzip.NewReader(bytes.NewReader(body))
		if gerr != nil {
			return fmt.Errorf("decompressing vulndb: %w", gerr)
		}
		jsonBody, err = io.ReadAll(io.LimitReader(r, 200*1024*1024))
		r.Close()
		if err != nil {
			return fmt.Errorf("decompressing vulndb: %w", err)
		}
	}

	var db struct {
		WordPress map[string][]json.RawMessage `json:"wordpress"`
		Plugins   map[string][]json.RawMessage `json:"plugins"`
		Themes    map[string][]json.RawMessage `json:"themes"`
	}
	if err := json.Unmarshal(jsonBody, &db); err != nil {
		return fmt.Errorf("invalid vulndb format: %w", err)
	}

	wpCount, pluginCount, themeCount := 0, 0, 0
	for _, v := range db.WordPress {
		wpCount += len(v)
	}
	for _, v := range db.Plugins {
		pluginCount += len(v)
	}
	for _, v := range db.Themes {
		themeCount += len(v)
	}

	localPath := data.VulnDBLocalPath()
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	if err := os.WriteFile(localPath, jsonBody, 0644); err != nil {
		return fmt.Errorf("writing vulndb: %w", err)
	}

	fmt.Printf("[+] Vulnerability database updated: %s\n", localPath)
	fmt.Printf("    WordPress: %d vulns across %d branches\n", wpCount, len(db.WordPress))
	fmt.Printf("    Plugins:   %d vulns across %d plugins\n", pluginCount, len(db.Plugins))
	fmt.Printf("    Themes:    %d vulns across %d themes\n", themeCount, len(db.Themes))
	fmt.Printf("    Total:     %d vulnerabilities\n", wpCount+pluginCount+themeCount)
	return nil
}

func fetchURL(client *http.Client, rawURL string) ([]byte, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return body, nil
}

func parseEnumerate(s string, opts *model.EnumerateOptions) {
	if s == "" {
		return
	}

	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(part) {
		case "p":
			opts.Plugins = true
		case "vp":
			opts.VulnerablePlugins = true
			opts.Plugins = true
		case "ap":
			opts.AllPlugins = true
			opts.Plugins = true
		case "t":
			opts.Themes = true
		case "vt":
			opts.VulnerableThemes = true
			opts.Themes = true
		case "at":
			opts.AllThemes = true
			opts.Themes = true
		case "u":
			opts.Users = true
		case "cb":
			opts.ConfigBackups = true
		case "dbe":
			opts.DBExports = true
		case "tt":
			opts.TimThumbs = true
		case "m":
			opts.Medias = true
		}
	}
}
