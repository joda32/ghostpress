package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type DetectionMode int

const (
	ModeMixed DetectionMode = iota
	ModePassive
	ModeAggressive
)

func ParseDetectionMode(s string) DetectionMode {
	switch strings.ToLower(s) {
	case "passive":
		return ModePassive
	case "aggressive":
		return ModeAggressive
	default:
		return ModeMixed
	}
}

func (m DetectionMode) String() string {
	switch m {
	case ModePassive:
		return "passive"
	case ModeAggressive:
		return "aggressive"
	default:
		return "mixed"
	}
}

type Reference struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (r Reference) URL() string {
	switch r.Type {
	case "cve":
		return "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + r.ID
	case "exploitdb":
		return "https://www.exploit-db.com/exploits/" + r.ID
	case "poc":
		return r.ID
	case "url":
		return r.ID
	case "wpvulndb":
		return "https://wpscan.com/vulnerability/" + r.ID
	default:
		return r.ID
	}
}

func (v Vulnerability) HasExploit() bool {
	for _, ref := range v.References {
		if ref.Type == "exploitdb" || ref.Type == "poc" {
			return true
		}
	}
	return false
}

// VersionRange is a single affected-version interval. An empty or "*" bound is
// unbounded on that side. It mirrors the Wordfence feed's affected_versions
// shape.
type VersionRange struct {
	FromVersion   string `json:"from_version,omitempty"`
	FromInclusive bool   `json:"from_inclusive,omitempty"`
	ToVersion     string `json:"to_version,omitempty"`
	ToInclusive   bool   `json:"to_inclusive,omitempty"`
}

// Contains reports whether ver falls inside the range. An unknown (empty)
// version is treated as a match so unknown installs are reported conservatively.
func (r VersionRange) Contains(ver string) bool {
	if ver == "" {
		return true
	}
	if r.FromVersion != "" && r.FromVersion != "*" {
		c := CompareVersions(ver, r.FromVersion)
		if c < 0 || (c == 0 && !r.FromInclusive) {
			return false
		}
	}
	if r.ToVersion != "" && r.ToVersion != "*" {
		c := CompareVersions(ver, r.ToVersion)
		if c > 0 || (c == 0 && !r.ToInclusive) {
			return false
		}
	}
	return true
}

type Vulnerability struct {
	Title      string         `json:"title"`
	Type       string         `json:"type,omitempty"`
	FixedIn    string         `json:"fixed_in,omitempty"`
	Affected   []VersionRange `json:"affected,omitempty"`
	References []Reference    `json:"references,omitempty"`
	CVSS       float64        `json:"cvss,omitempty"`
}

// AffectsVersion reports whether ver is vulnerable. When explicit affected
// ranges are present they are authoritative; otherwise it falls back to the
// legacy "< fixed_in" semantics (and "affects all" when fixed_in is empty).
func (v Vulnerability) AffectsVersion(ver string) bool {
	if len(v.Affected) > 0 {
		for _, r := range v.Affected {
			if r.Contains(ver) {
				return true
			}
		}
		return false
	}
	if v.FixedIn == "" {
		return true
	}
	return CompareVersions(ver, v.FixedIn) < 0
}

type InterestingFinding struct {
	URL                string      `json:"url"`
	Type               string      `json:"type"`
	Description        string      `json:"description"`
	InterestingEntries []string    `json:"interesting_entries,omitempty"`
	References         []Reference `json:"references,omitempty"`
	Confidence         int         `json:"confidence"`
	FoundBy            string      `json:"found_by"`
}

type WPVersion struct {
	Number             string          `json:"number"`
	FoundBy            string          `json:"found_by"`
	Confidence         int             `json:"confidence"`
	InterestingEntries []string        `json:"interesting_entries,omitempty"`
	Vulnerabilities    []Vulnerability `json:"vulnerabilities,omitempty"`
	Status             string          `json:"status"`
}

type Plugin struct {
	Slug               string          `json:"slug"`
	Version            string          `json:"version,omitempty"`
	LatestVersion      string          `json:"latest_version,omitempty"`
	Location           string          `json:"location"`
	FoundBy            string          `json:"found_by"`
	Confidence         int             `json:"confidence"`
	InterestingEntries []string        `json:"interesting_entries,omitempty"`
	Vulnerabilities    []Vulnerability `json:"vulnerabilities,omitempty"`
	Outdated           bool            `json:"outdated,omitempty"`
	DirectoryListing   bool            `json:"directory_listing,omitempty"`
	ErrorLog           bool            `json:"error_log,omitempty"`
	VersionBlocked     bool            `json:"version_blocked,omitempty"`
	KnownVulnCount     int             `json:"known_vuln_count,omitempty"`
	// UnconfirmedVulns holds every vulnerability known for this slug across all
	// versions, populated only when the version could not be determined. They are
	// NOT confirmed to apply to the installed version and are excluded from the
	// confirmed-vuln totals; shown in the CLI only under --show-unconfirmed.
	UnconfirmedVulns []Vulnerability `json:"unconfirmed_vulns,omitempty"`
}

type Theme struct {
	Slug               string          `json:"slug"`
	Version            string          `json:"version,omitempty"`
	LatestVersion      string          `json:"latest_version,omitempty"`
	Location           string          `json:"location"`
	FoundBy            string          `json:"found_by"`
	Confidence         int             `json:"confidence"`
	InterestingEntries []string        `json:"interesting_entries,omitempty"`
	Vulnerabilities    []Vulnerability `json:"vulnerabilities,omitempty"`
	Outdated           bool            `json:"outdated,omitempty"`
	DirectoryListing   bool            `json:"directory_listing,omitempty"`
	StyleName          string          `json:"style_name,omitempty"`
	StyleURI           string          `json:"style_uri,omitempty"`
	Author             string          `json:"author,omitempty"`
	AuthorURI          string          `json:"author_uri,omitempty"`
	VersionBlocked     bool            `json:"version_blocked,omitempty"`
	KnownVulnCount     int             `json:"known_vuln_count,omitempty"`
	// UnconfirmedVulns: see Plugin.UnconfirmedVulns.
	UnconfirmedVulns []Vulnerability `json:"unconfirmed_vulns,omitempty"`
}

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	FoundBy    string `json:"found_by"`
	Confidence int    `json:"confidence"`
}

type Media struct {
	URL        string `json:"url"`
	Title      string `json:"title,omitempty"`
	FoundBy    string `json:"found_by"`
	Confidence int    `json:"confidence"`
}

type PasswordResult struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TargetInfo struct {
	URL            string `json:"url"`
	EffectiveURL   string `json:"effective_url"`
	IP             string `json:"ip"`
	Server         string `json:"server,omitempty"`
	WordPressFound bool   `json:"wordpress_found"`
	ContentDir     string `json:"content_dir"`
	PluginsDir     string `json:"plugins_dir"`
}

type ScanResult struct {
	Target              TargetInfo           `json:"target"`
	StartTime           time.Time            `json:"start_time"`
	EndTime             time.Time            `json:"end_time"`
	InterestingFindings []InterestingFinding `json:"interesting_findings,omitempty"`
	Version             *WPVersion           `json:"version,omitempty"`
	MainTheme           *Theme               `json:"main_theme,omitempty"`
	Plugins             []Plugin             `json:"plugins,omitempty"`
	Themes              []Theme              `json:"themes,omitempty"`
	Users               []User               `json:"users,omitempty"`
	ConfigBackups       []string             `json:"config_backups,omitempty"`
	DBExports           []string             `json:"db_exports,omitempty"`
	TimThumbs           []string             `json:"timthumbs,omitempty"`
	Media               []Media              `json:"media,omitempty"`
	PasswordResults     []PasswordResult     `json:"password_results,omitempty"`
	RequestsDone        int                  `json:"requests_done"`
	DataSent            int64                `json:"data_sent"`
	DataReceived        int64                `json:"data_received"`
	RateLimited         int                  `json:"rate_limited,omitempty"`
	Forbidden           int                  `json:"forbidden,omitempty"`
	Error               string               `json:"error,omitempty"`
}

func (r *ScanResult) Vulnerable() bool {
	if r.Version != nil && len(r.Version.Vulnerabilities) > 0 {
		return true
	}
	for _, p := range r.Plugins {
		if len(p.Vulnerabilities) > 0 {
			return true
		}
	}
	for _, t := range r.Themes {
		if len(t.Vulnerabilities) > 0 {
			return true
		}
	}
	return len(r.PasswordResults) > 0
}

type ScanOptions struct {
	URL              string
	DetectionMode    DetectionMode
	Enumerate        EnumerateOptions
	Threads          int
	ThrottleMillis   int
	UserAgent        string
	RandomUserAgent  bool
	Proxy            string
	ProxyAuth        string
	CookieString     string
	Headers          map[string]string
	HTTPAuth         string
	ConnectTimeout   int
	RequestTimeout   int
	MaxRedirects     int
	Force            bool
	Stealthy         bool
	OutputFormat     string
	OutputFile       string
	DisableTLSChecks bool
	Debug            bool
	ShowUnconfirmed  bool

	Passwords      string
	Usernames      []string
	PasswordAttack string
	LoginURI       string

	PluginsSlugs string
	ThemesSlugs  string
	UsersRange   string
	MediaRange   string
}

type EnumerateOptions struct {
	Plugins           bool
	VulnerablePlugins bool
	AllPlugins        bool
	Themes            bool
	VulnerableThemes  bool
	AllThemes         bool
	Users             bool
	TimThumbs         bool
	ConfigBackups     bool
	DBExports         bool
	Medias            bool
}

func (e EnumerateOptions) Any() bool {
	return e.Plugins || e.VulnerablePlugins || e.AllPlugins ||
		e.Themes || e.VulnerableThemes || e.AllThemes ||
		e.Users || e.TimThumbs || e.ConfigBackups || e.DBExports || e.Medias
}

func CompareVersions(a, b string) int {
	pa := parseVersionParts(a)
	pb := parseVersionParts(b)
	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}
	for i := 0; i < maxLen; i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

func parseVersionParts(v string) []int {
	parts := strings.Split(strings.TrimSpace(v), ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil {
			for i, c := range p {
				if c < '0' || c > '9' {
					n, _ = strconv.Atoi(p[:i])
					break
				}
			}
		}
		result = append(result, n)
	}
	return result
}

func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
