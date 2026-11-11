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
	"ghostpress/wp"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	// vulnDBURL is where `ghostpress update` fetches the vulnerability database
	// from by default. It points at the rolling "vulndb-latest" release asset in
	// the joda32/ghostpress repo, which the update-vulndb workflow republishes
	// from the Wordfence feed. Override with --url, or at build time via
	// -ldflags "-X main.vulnDBURL=...".
	vulnDBURL = "https://github.com/joda32/ghostpress/releases/download/vulndb-latest/vulndb.json.gz"
	// signaturesURL is where `ghostpress update` fetches the WAF/misconfiguration
	// signatures from by default - a rolling release asset, like the vuln DB.
	// Override with --signatures-url or at build time via -ldflags.
	signaturesURL = "https://github.com/joda32/ghostpress/releases/download/signatures-latest/signatures.json"
	// fingerprintsURL is where `ghostpress update` fetches the WordPress core
	// version-fingerprint DB from by default - a rolling release asset, like the
	// vuln DB. Refreshing it lets ghostpress fingerprint newly released WordPress
	// versions without a rebuild. Override with --fingerprints-url or -ldflags.
	fingerprintsURL = "https://github.com/joda32/ghostpress/releases/download/fingerprints-latest/wp_fingerprints.json"
)

func main() {
	var opts model.ScanOptions
	var enumerate string

	rootCmd := &cobra.Command{
		Use:   "ghostpress [flags] URL",
		Short: "WordPress Security Auditor",
		Long:  "Ghostpress - A fast, portable WordPress security scanner written in Go.",
		Args:  cobra.ExactArgs(1),
		// Errors are surfaced by the scanner/report itself; don't dump the full
		// usage text after a runtime failure (e.g. TLS error, connection refused).
		SilenceUsage: true,
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
	flags.BoolVar(&opts.ShowUnconfirmed, "show-unconfirmed", false, "List vulnerabilities for components whose version could not be detected (shown with a warning; may not apply to the installed version)")

	flags.StringVarP(&enumerate, "enumerate", "e", "", "Enumeration options (p,vp,ap,t,vt,at,u,cb,dbe,tt,m)")
	flags.StringVar(&opts.UsersRange, "users-range", "10", "User ID range for brute forcing (default: 10)")
	flags.StringVar(&opts.MediaRange, "media-range", "50", "Attachment ID range for media brute forcing (default: 50)")
	flags.StringVar(&opts.PluginsSlugs, "plugins-list", "", "File of plugin slugs to check (one per line; default: built-in popular list)")
	flags.StringVar(&opts.ThemesSlugs, "themes-list", "", "File of theme slugs to check (one per line; default: built-in popular list)")
	flags.StringVar(&opts.SignaturesFile, "signatures", "", "File of WAF/misconfiguration signatures to use (JSON; default: ~/.ghostpress/signatures.json or the built-in set)")
	flags.StringVar(&opts.FingerprintsFile, "fingerprints", "", "File of WordPress core version fingerprints to use (JSON; default: ~/.ghostpress/wp_fingerprints.json or the built-in set)")
	flags.BoolVar(&opts.NoWPAPI, "no-wp-api", false, "Disable api.wordpress.org checksum verification of the core version (keeps detection fully offline)")

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

	var updateURL, updateSigURL, updateFpURL string
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update the vulnerability database, signatures, and version fingerprints",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := updateVulnDB(updateURL); err != nil {
				return err
			}
			if err := updateSignatures(updateSigURL); err != nil {
				return err
			}
			return updateFingerprints(updateFpURL)
		},
	}
	updateCmd.Flags().StringVar(&updateURL, "url", vulnDBURL, "URL to fetch vulndb.json from")
	updateCmd.Flags().StringVar(&updateSigURL, "signatures-url", signaturesURL, "URL to fetch signatures.json from")
	updateCmd.Flags().StringVar(&updateFpURL, "fingerprints-url", fingerprintsURL, "URL to fetch wp_fingerprints.json from")
	rootCmd.AddCommand(updateCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(opts model.ScanOptions, enumerate string) error {
	data.SetSignaturesOverride(opts.SignaturesFile)
	data.SetFingerprintsOverride(opts.FingerprintsFile)
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
		formatter = output.NewCLI(noColor, outFile, opts.ShowUnconfirmed, version, wp.VulnDBCount())
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
		// The failure was already shown (scanner's error line, or the report's
		// "WordPress not detected" notice). Exit non-zero without returning the
		// error, so cobra doesn't print a redundant second copy.
		os.Exit(1)
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

// updateSignatures refreshes the WAF/misconfiguration signatures from a release
// asset. It is best-effort: a missing or unreachable asset (e.g. not published
// yet) warns rather than failing the whole update, so the vuln-DB refresh still
// counts.
func updateSignatures(rawURL string) error {
	if rawURL == "" {
		return nil
	}

	fmt.Printf("[*] Downloading signatures from:\n    %s\n", rawURL)

	client := &http.Client{Timeout: 60 * time.Second}

	body, err := fetchURL(client, rawURL)
	if err != nil {
		fmt.Printf("[!] Signatures not updated: %v\n", err)
		return nil
	}

	if sum, serr := fetchURL(client, rawURL+".sha256"); serr == nil {
		want := strings.ToLower(strings.Fields(string(sum))[0])
		got := fmt.Sprintf("%x", sha256.Sum256(body))
		if _, derr := hex.DecodeString(want); derr == nil && want != got {
			fmt.Printf("[!] Signatures checksum mismatch; not updated\n")
			return nil
		}
		fmt.Printf("[*] Checksum verified\n")
	}

	jsonBody := body
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		r, gerr := gzip.NewReader(bytes.NewReader(body))
		if gerr != nil {
			fmt.Printf("[!] Signatures not updated: %v\n", gerr)
			return nil
		}
		jsonBody, err = io.ReadAll(io.LimitReader(r, 50*1024*1024))
		r.Close()
		if err != nil {
			fmt.Printf("[!] Signatures not updated: %v\n", err)
			return nil
		}
	}

	var sig struct {
		WAF       []json.RawMessage `json:"waf"`
		Misconfig []json.RawMessage `json:"misconfig"`
	}
	if err := json.Unmarshal(jsonBody, &sig); err != nil {
		fmt.Printf("[!] Signatures not updated: invalid format: %v\n", err)
		return nil
	}

	localPath := data.SignaturesLocalPath()
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	if err := os.WriteFile(localPath, jsonBody, 0644); err != nil {
		return fmt.Errorf("writing signatures: %w", err)
	}

	fmt.Printf("[+] Signatures updated: %s\n", localPath)
	fmt.Printf("    WAF signatures:   %d\n", len(sig.WAF))
	fmt.Printf("    Misconfig checks: %d\n", len(sig.Misconfig))
	return nil
}

// updateFingerprints refreshes the WordPress core version-fingerprint DB from a
// release asset. Like updateSignatures it is best-effort: a missing or
// unreachable asset warns rather than failing the update, so the rest still
// counts. Refreshing it is how ghostpress learns to fingerprint WordPress
// versions released after the binary was built.
func updateFingerprints(rawURL string) error {
	if rawURL == "" {
		return nil
	}

	fmt.Printf("[*] Downloading version fingerprints from:\n    %s\n", rawURL)

	client := &http.Client{Timeout: 60 * time.Second}

	body, err := fetchURL(client, rawURL)
	if err != nil {
		fmt.Printf("[!] Fingerprints not updated: %v\n", err)
		return nil
	}

	if sum, serr := fetchURL(client, rawURL+".sha256"); serr == nil {
		want := strings.ToLower(strings.Fields(string(sum))[0])
		got := fmt.Sprintf("%x", sha256.Sum256(body))
		if _, derr := hex.DecodeString(want); derr == nil && want != got {
			fmt.Printf("[!] Fingerprints checksum mismatch; not updated\n")
			return nil
		}
		fmt.Printf("[*] Checksum verified\n")
	}

	jsonBody := body
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		r, gerr := gzip.NewReader(bytes.NewReader(body))
		if gerr != nil {
			fmt.Printf("[!] Fingerprints not updated: %v\n", gerr)
			return nil
		}
		jsonBody, err = io.ReadAll(io.LimitReader(r, 50*1024*1024))
		r.Close()
		if err != nil {
			fmt.Printf("[!] Fingerprints not updated: %v\n", err)
			return nil
		}
	}

	// Validate shape: {filepath: {md5: [versions...]}}.
	var fp map[string]map[string][]string
	if err := json.Unmarshal(jsonBody, &fp); err != nil {
		fmt.Printf("[!] Fingerprints not updated: invalid format: %v\n", err)
		return nil
	}

	localPath := data.FingerprintsLocalPath()
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	if err := os.WriteFile(localPath, jsonBody, 0644); err != nil {
		return fmt.Errorf("writing fingerprints: %w", err)
	}

	fmt.Printf("[+] Version fingerprints updated: %s\n", localPath)
	fmt.Printf("    Fingerprinted files: %d\n", len(fp))
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
