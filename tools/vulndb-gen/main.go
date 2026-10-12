// Command vulndb-gen builds the ghostpress vulnerability database
// (data/vulndb.json[.gz]) from the Wordfence Intelligence v3 vulnerability feed,
// optionally enriched with ExploitDB and GitHub PoC references.
//
// The Wordfence feed is the authoritative source for WordPress core, plugin and
// theme vulnerabilities: it provides the real plugin/theme SLUG (not the
// marketing product name), structured affected-version ranges, CVE, CVSS and
// CWE. A valid Wordfence Intelligence API key is required to fetch it (via
// --wf-api-key or the WORDFENCE_API_KEY environment variable); alternatively a
// previously-downloaded feed file can be processed with --feed-file.
//
// LICENSE/ATTRIBUTION: the Wordfence feed is licensed by Defiant Inc. Each copy
// of the data must reproduce Defiant's copyright notice and license and include
// a hyperlink to each vulnerability record. This tool preserves every record's
// Wordfence reference URL and copies the license text into the output's _meta
// block. Do not remove either.
package main

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	wfFeedBase      = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities"
	exploitDBCSVURL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	pocGitHubBase   = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
)

func main() {
	apiKey := flag.String("wf-api-key", os.Getenv("WORDFENCE_API_KEY"), "Wordfence Intelligence API key (or set WORDFENCE_API_KEY)")
	feed := flag.String("feed", "production", "Wordfence feed to use (production, scanner)")
	feedFile := flag.String("feed-file", "", "Process a pre-downloaded feed file instead of fetching")
	dataDir := flag.String("data-dir", "../data", "Path to the scanner's data directory (output)")
	outputFile := flag.String("o", "", "Output file (default stdout; use - for <data-dir>/vulndb.json.gz; a .gz suffix gzips)")
	noExploits := flag.Bool("no-exploits", false, "Skip ExploitDB enrichment")
	githubPoCs := flag.Bool("github-pocs", false, "Also enrich with GitHub PoC references (one request per CVE; slow)")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	raw, err := loadFeed(*feedFile, *feed, *apiKey, *verbose)
	if err != nil {
		log.Fatalf("Failed to load Wordfence feed: %v", err)
	}

	var feedData map[string]wfRecord
	if err := json.Unmarshal(raw, &feedData); err != nil {
		log.Fatalf("Failed to parse Wordfence feed: %v", err)
	}
	log.Printf("Loaded %d records from Wordfence feed", len(feedData))

	db := buildDB(feedData, *verbose)

	if !*noExploits {
		enrichWithExploits(db, *githubPoCs, *verbose)
	}

	db.Meta.Generated = time.Now().UTC().Format(time.RFC3339)
	db.Meta.Source = "Wordfence Intelligence v3"
	printStats(db)

	if err := writeOutput(db, *outputFile, *dataDir); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
}

// ---- Wordfence feed schema ----

type wfRecord struct {
	ID            string       `json:"id"`
	Title         string       `json:"title"`
	CVE           string       `json:"cve"`
	CVELink       string       `json:"cve_link"`
	CVSS          wfCVSS       `json:"cvss"`
	CWE           *wfCWE       `json:"cwe"`
	Description   string       `json:"description"`
	Informational bool         `json:"informational"`
	References    []string     `json:"references"`
	Software      []wfSoftware `json:"software"`
	Copyrights    wfCopyrights `json:"copyrights"`
}

type wfCopyrights struct {
	Message string      `json:"message"`
	Defiant wfCopyright `json:"defiant"`
}

type wfCVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
	Rating string  `json:"rating"`
}

type wfCWE struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type wfSoftware struct {
	Type             string             `json:"type"`
	Name             string             `json:"name"`
	Slug             string             `json:"slug"`
	AffectedVersions map[string]wfRange `json:"affected_versions"`
	Patched          bool               `json:"patched"`
	PatchedVersions  []string           `json:"patched_versions"`
}

type wfRange struct {
	FromVersion   string `json:"from_version"`
	FromInclusive bool   `json:"from_inclusive"`
	ToVersion     string `json:"to_version"`
	ToInclusive   bool   `json:"to_inclusive"`
}

type wfCopyright struct {
	Notice     string `json:"notice"`
	License    string `json:"license"`
	LicenseURL string `json:"license_url"`
}

// ---- output schema (consumed by model.Vulnerability) ----

type vulnDB struct {
	WordPress map[string][]vulnEntry `json:"wordpress"`
	Plugins   map[string][]vulnEntry `json:"plugins"`
	Themes    map[string][]vulnEntry `json:"themes"`
	Meta      dbMeta                 `json:"_meta"`
}

type dbMeta struct {
	Generated string       `json:"generated"`
	Source    string       `json:"source"`
	Total     int          `json:"total"`
	License   *licenseMeta `json:"license,omitempty"`
}

type licenseMeta struct {
	Notice  string `json:"notice"`
	License string `json:"license"`
	URL     string `json:"url"`
}

type vulnEntry struct {
	Title      string         `json:"title"`
	Type       string         `json:"type,omitempty"`
	FixedIn    string         `json:"fixed_in,omitempty"`
	Affected   []versionRange `json:"affected,omitempty"`
	CVSS       float64        `json:"cvss,omitempty"`
	References []refEntry     `json:"references,omitempty"`
}

type versionRange struct {
	FromVersion   string `json:"from_version,omitempty"`
	FromInclusive bool   `json:"from_inclusive,omitempty"`
	ToVersion     string `json:"to_version,omitempty"`
	ToInclusive   bool   `json:"to_inclusive,omitempty"`
}

type refEntry struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func loadFeed(feedFile, feed, apiKey string, verbose bool) ([]byte, error) {
	if feedFile != "" {
		log.Printf("Reading feed from %s", feedFile)
		return os.ReadFile(feedFile)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("no Wordfence API key (set --wf-api-key or WORDFENCE_API_KEY), or pass --feed-file")
	}
	url := fmt.Sprintf("%s/%s", wfFeedBase, feed)
	log.Printf("Fetching Wordfence %s feed...", feed)

	client := &http.Client{Timeout: 10 * time.Minute}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("User-Agent", "ghostpress-vulndb-gen")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else if resp.StatusCode == 200 {
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			if resp.StatusCode == 429 {
				log.Printf("  rate limited, waiting 60s (attempt %d)...", attempt+1)
				time.Sleep(60 * time.Second)
				continue
			}
		}
		if attempt < 3 {
			time.Sleep(10 * time.Second)
		}
	}
	return nil, lastErr
}

func buildDB(feed map[string]wfRecord, verbose bool) *vulnDB {
	db := &vulnDB{
		WordPress: make(map[string][]vulnEntry),
		Plugins:   make(map[string][]vulnEntry),
		Themes:    make(map[string][]vulnEntry),
	}

	for _, rec := range feed {
		if rec.Informational {
			continue
		}
		if db.Meta.License == nil && rec.Copyrights.Defiant.License != "" {
			c := rec.Copyrights.Defiant
			db.Meta.License = &licenseMeta{Notice: c.Notice, License: c.License, URL: c.LicenseURL}
		}

		refs := make([]refEntry, 0, len(rec.References)+1)
		if rec.CVE != "" {
			refs = append(refs, refEntry{Type: "cve", ID: rec.CVE})
		}
		for _, u := range rec.References {
			refs = append(refs, refEntry{Type: "url", ID: u})
		}

		vtype := classifyType(rec)

		for _, sw := range rec.Software {
			entry := vulnEntry{
				Title:      rec.Title,
				Type:       vtype,
				CVSS:       rec.CVSS.Score,
				Affected:   convertRanges(sw.AffectedVersions),
				References: refs,
			}
			if len(sw.PatchedVersions) > 0 {
				entry.FixedIn = sw.PatchedVersions[0]
			}

			switch sw.Type {
			case "core":
				db.WordPress["wordpress"] = append(db.WordPress["wordpress"], entry)
			case "plugin":
				if sw.Slug != "" {
					db.Plugins[sw.Slug] = append(db.Plugins[sw.Slug], entry)
				}
			case "theme":
				if sw.Slug != "" {
					db.Themes[sw.Slug] = append(db.Themes[sw.Slug], entry)
				}
			}
		}
	}

	sortDB(db)
	return db
}

func convertRanges(avs map[string]wfRange) []versionRange {
	ranges := make([]versionRange, 0, len(avs))
	for _, r := range avs {
		ranges = append(ranges, versionRange{
			FromVersion:   r.FromVersion,
			FromInclusive: r.FromInclusive,
			ToVersion:     r.ToVersion,
			ToInclusive:   r.ToInclusive,
		})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].ToVersion < ranges[j].ToVersion })
	return ranges
}

var cweTypeMap = map[int]string{
	79:  "XSS",
	80:  "XSS",
	89:  "SQLI",
	94:  "RCE",
	95:  "RCE",
	98:  "RCE",
	352: "CSRF",
	918: "SSRF",
	22:  "Path Traversal",
	23:  "Path Traversal",
	434: "Arbitrary File Upload",
	862: "Authorization Bypass",
	863: "Authorization Bypass",
	502: "Object Injection",
	601: "Open Redirect",
	200: "Information Disclosure",
	209: "Information Disclosure",
	287: "Authentication Bypass",
	306: "Authentication Bypass",
}

func classifyType(rec wfRecord) string {
	if rec.CWE != nil {
		if t, ok := cweTypeMap[rec.CWE.ID]; ok {
			return t
		}
	}
	desc := strings.ToLower(rec.Title + " " + rec.Description)
	switch {
	case strings.Contains(desc, "sql injection"):
		return "SQLI"
	case strings.Contains(desc, "cross-site scripting") || strings.Contains(desc, " xss"):
		return "XSS"
	case strings.Contains(desc, "remote code execution"):
		return "RCE"
	case strings.Contains(desc, "cross-site request forgery") || strings.Contains(desc, " csrf"):
		return "CSRF"
	case strings.Contains(desc, "server-side request forgery") || strings.Contains(desc, " ssrf"):
		return "SSRF"
	case strings.Contains(desc, "file upload"):
		return "Arbitrary File Upload"
	case strings.Contains(desc, "path traversal") || strings.Contains(desc, "directory traversal"):
		return "Path Traversal"
	case strings.Contains(desc, "open redirect"):
		return "Open Redirect"
	case strings.Contains(desc, "authentication bypass"):
		return "Authentication Bypass"
	case strings.Contains(desc, "privilege escalation") || strings.Contains(desc, "authorization"):
		return "Authorization Bypass"
	case strings.Contains(desc, "information disclosure") || strings.Contains(desc, "information exposure"):
		return "Information Disclosure"
	}
	return ""
}

func sortDB(db *vulnDB) {
	for _, m := range []map[string][]vulnEntry{db.WordPress, db.Plugins, db.Themes} {
		for k, vulns := range m {
			sort.Slice(vulns, func(i, j int) bool { return vulns[i].CVSS > vulns[j].CVSS })
			m[k] = vulns
		}
	}
}

func writeOutput(db *vulnDB, outputFile, dataDir string) error {
	db.Meta.Total = countVulns(db)

	out := os.Stdout
	gzipOut := false
	if outputFile != "" {
		if outputFile == "-" {
			outputFile = filepath.Join(dataDir, "vulndb.json.gz")
		}
		f, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
		gzipOut = strings.HasSuffix(outputFile, ".gz")
		log.Printf("Writing to %s", outputFile)
	}

	var w io.Writer = out
	if gzipOut {
		gz, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
		defer gz.Close()
		w = gz
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(db)
}

func countVulns(db *vulnDB) int {
	n := 0
	for _, m := range []map[string][]vulnEntry{db.WordPress, db.Plugins, db.Themes} {
		for _, v := range m {
			n += len(v)
		}
	}
	return n
}

func printStats(db *vulnDB) {
	wp, pl, th := 0, 0, 0
	for _, v := range db.WordPress {
		wp += len(v)
	}
	for _, v := range db.Plugins {
		pl += len(v)
	}
	for _, v := range db.Themes {
		th += len(v)
	}
	exploit := 0
	for _, m := range []map[string][]vulnEntry{db.WordPress, db.Plugins, db.Themes} {
		for _, vulns := range m {
			for _, v := range vulns {
				for _, r := range v.References {
					if r.Type == "exploitdb" || r.Type == "poc" {
						exploit++
						break
					}
				}
			}
		}
	}
	log.Println("Database stats:")
	log.Printf("  WordPress core: %d vulns", wp)
	log.Printf("  Plugins: %d vulns across %d plugins", pl, len(db.Plugins))
	log.Printf("  Themes: %d vulns across %d themes", th, len(db.Themes))
	log.Printf("  Total: %d vulnerabilities (%d with known exploits)", wp+pl+th, exploit)
}

// ---- enrichment (ExploitDB + optional GitHub PoC), keyed by CVE ----

func enrichWithExploits(db *vulnDB, githubPoCs, verbose bool) {
	cveToRefs := make(map[string][]refEntry)

	edbCount := fetchExploitDB(cveToRefs, verbose)
	pocCount := 0
	if githubPoCs {
		pocCount = fetchGitHubPoCs(db, cveToRefs, verbose)
	}
	if edbCount+pocCount == 0 {
		return
	}

	enriched := 0
	for _, m := range []map[string][]vulnEntry{db.WordPress, db.Plugins, db.Themes} {
		for slug, vulns := range m {
			for i := range vulns {
				cve := cveOf(vulns[i])
				if cve == "" {
					continue
				}
				if refs, ok := cveToRefs[cve]; ok {
					vulns[i].References = append(vulns[i].References, refs...)
					enriched++
				}
			}
			m[slug] = vulns
		}
	}
	log.Printf("Exploit enrichment: %d ExploitDB + %d GitHub PoCs mapped, %d vulns enriched", edbCount, pocCount, enriched)
}

func cveOf(e vulnEntry) string {
	for _, r := range e.References {
		if r.Type == "cve" {
			return r.ID
		}
	}
	return ""
}

func fetchExploitDB(cveToRefs map[string][]refEntry, verbose bool) int {
	log.Println("Fetching ExploitDB database...")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(exploitDBCSVURL)
	if err != nil {
		log.Printf("  Warning: ExploitDB fetch failed: %v", err)
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("  Warning: ExploitDB returned HTTP %d", resp.StatusCode)
		return 0
	}

	reader := csv.NewReader(resp.Body)
	reader.LazyQuotes = true
	header, err := reader.Read()
	if err != nil {
		log.Printf("  Warning: ExploitDB CSV header error: %v", err)
		return 0
	}
	idCol, codesCol, descCol := -1, -1, -1
	for i, h := range header {
		switch strings.TrimSpace(h) {
		case "id":
			idCol = i
		case "codes":
			codesCol = i
		case "description":
			descCol = i
		}
	}
	if idCol < 0 || codesCol < 0 {
		log.Printf("  Warning: ExploitDB CSV missing required columns")
		return 0
	}

	count := 0
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if codesCol >= len(record) || idCol >= len(record) {
			continue
		}
		edbID := strings.TrimSpace(record[idCol])
		codes := strings.TrimSpace(record[codesCol])
		if codes == "" || edbID == "" {
			continue
		}
		desc := ""
		if descCol >= 0 && descCol < len(record) {
			desc = strings.ToLower(record[descCol])
		}
		if !strings.Contains(desc, "wordpress") && !strings.Contains(desc, "wp ") {
			continue
		}
		ref := refEntry{Type: "exploitdb", ID: edbID}
		for _, code := range strings.Split(codes, ";") {
			code = strings.TrimSpace(code)
			if strings.HasPrefix(code, "CVE-") {
				cveToRefs[code] = append(cveToRefs[code], ref)
				count++
			}
		}
	}
	log.Printf("  ExploitDB: %d CVE-to-exploit mappings from WordPress entries", count)
	return count
}

func fetchGitHubPoCs(db *vulnDB, cveToRefs map[string][]refEntry, verbose bool) int {
	log.Println("Fetching GitHub PoC references...")
	cves := collectCVEs(db)
	if len(cves) == 0 {
		return 0
	}
	byYear := make(map[string][]string)
	for _, cve := range cves {
		parts := strings.SplitN(cve, "-", 3)
		if len(parts) >= 2 {
			byYear[parts[1]] = append(byYear[parts[1]], cve)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	count := 0
	for year, yearCVEs := range byYear {
		url := fmt.Sprintf("%s/%s/", pocGitHubBase, year)
		for _, cve := range yearCVEs {
			resp, err := client.Get(url + cve + ".json")
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				continue
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			resp.Body.Close()
			if err != nil {
				continue
			}
			var pocs []struct {
				HTMLURL string `json:"html_url"`
				Stars   int    `json:"stargazers_count"`
			}
			if err := json.Unmarshal(body, &pocs); err != nil {
				continue
			}
			for _, poc := range pocs {
				if poc.Stars < 2 {
					continue
				}
				cveToRefs[cve] = append(cveToRefs[cve], refEntry{Type: "poc", ID: poc.HTMLURL})
				count++
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	log.Printf("  GitHub PoCs: %d repos linked (stars >= 2)", count)
	return count
}

func collectCVEs(db *vulnDB) []string {
	seen := make(map[string]bool)
	for _, m := range []map[string][]vulnEntry{db.WordPress, db.Plugins, db.Themes} {
		for _, vulns := range m {
			for _, v := range vulns {
				if cve := cveOf(v); cve != "" {
					seen[cve] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for cve := range seen {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}
