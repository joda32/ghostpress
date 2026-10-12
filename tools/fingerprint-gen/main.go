// Command fingerprint-gen builds data/wp_fingerprints.json: a map of
//
//	path -> md5(file contents) -> [WordPress versions with that hash]
//
// used by the scanner's aggressive version fingerprinting. It fetches each
// tracked static file from the WordPress core Subversion tags
// (https://core.svn.wordpress.org/tags/<version>/<path>) for every release it
// is told about, so only a handful of small files are downloaded per version
// rather than the full release zip.
//
// The list of files to fingerprint is read from the keys of the existing
// <data-dir>/wp_fingerprints.json on disk, so that file remains the single
// source of truth for which paths matter.
package main

import (
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const svnTagsBase = "https://core.svn.wordpress.org/tags"

var defaultPaths = []string{
	"wp-admin/css/install.css",
	"wp-includes/js/jquery/jquery.js",
	"wp-includes/css/dist/block-library/style.min.css",
	"readme.html",
}

func main() {
	dataDir := flag.String("data-dir", "../data", "Path to the scanner's data directory (fingerprint path list + output)")
	outputFile := flag.String("o", "", "Output file (default: stdout, use - for <data-dir>/wp_fingerprints.json)")
	versionsArg := flag.String("versions", "", "Comma-separated versions to fingerprint (default: all tags >= -min)")
	minVersion := flag.String("min", "4.0", "Minimum version to include when auto-listing tags")
	threads := flag.Int("threads", 8, "Number of concurrent downloads")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	paths := fingerprintPaths(*dataDir)
	log.Printf("Fingerprinting %d file(s): %s", len(paths), strings.Join(paths, ", "))

	versions, err := resolveVersions(*versionsArg, *minVersion)
	if err != nil {
		log.Fatalf("Failed to resolve versions: %v", err)
	}
	log.Printf("Fingerprinting %d WordPress release(s)", len(versions))

	fp := buildFingerprints(versions, paths, *threads, *verbose)

	printStats(fp)

	out := os.Stdout
	if *outputFile != "" {
		if *outputFile == "-" {
			*outputFile = filepath.Join(*dataDir, "wp_fingerprints.json")
		}
		f, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer f.Close()
		out = f
		log.Printf("Writing to %s", *outputFile)
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fp); err != nil {
		log.Fatalf("Failed to encode JSON: %v", err)
	}
}

// fingerprintPaths reads the file list from the keys of the on-disk fingerprint
// DB, falling back to a built-in default list.
func fingerprintPaths(dataDir string) []string {
	raw, err := os.ReadFile(filepath.Join(dataDir, "wp_fingerprints.json"))
	if err == nil {
		var existing map[string]map[string][]string
		if err := json.Unmarshal(raw, &existing); err == nil && len(existing) > 0 {
			paths := make([]string, 0, len(existing))
			for p := range existing {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			return paths
		}
	}
	return defaultPaths
}

func resolveVersions(versionsArg, minVersion string) ([]string, error) {
	if versionsArg != "" {
		var versions []string
		for _, v := range strings.Split(versionsArg, ",") {
			if v = strings.TrimSpace(v); v != "" {
				versions = append(versions, v)
			}
		}
		return versions, nil
	}

	log.Println("Listing WordPress release tags from SVN...")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(svnTagsBase + "/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("SVN tags listing returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`href="([0-9][0-9.]*)/"`)
	seen := make(map[string]bool)
	var versions []string
	for _, m := range re.FindAllStringSubmatch(string(body), -1) {
		v := m[1]
		if seen[v] {
			continue
		}
		seen[v] = true
		if minVersion != "" && compareVersions(v, minVersion) < 0 {
			continue
		}
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})
	return versions, nil
}

// compareVersions compares dotted numeric versions, tolerating non-numeric
// suffixes. Mirrors model.CompareVersions; kept local so this tool stays a
// standalone module with no dependency on the scanner.
func compareVersions(a, b string) int {
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

type task struct {
	version string
	path    string
}

func buildFingerprints(versions, paths []string, threads int, verbose bool) map[string]map[string][]string {
	if threads <= 0 {
		threads = 8
	}

	fp := make(map[string]map[string][]string)
	for _, p := range paths {
		fp[p] = make(map[string][]string)
	}

	tasks := make(chan task)
	var mu sync.Mutex
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				hash, ok := fetchHash(client, t.version, t.path)
				if !ok {
					continue
				}
				mu.Lock()
				fp[t.path][hash] = append(fp[t.path][hash], t.version)
				mu.Unlock()
				if verbose {
					log.Printf("  %s %s -> %s", t.version, t.path, hash)
				}
			}
		}()
	}

	for _, v := range versions {
		for _, p := range paths {
			tasks <- task{version: v, path: p}
		}
	}
	close(tasks)
	wg.Wait()

	// Deduplicate and sort the version list for each hash.
	for path, hashMap := range fp {
		for hash, vers := range hashMap {
			seen := make(map[string]bool)
			var uniq []string
			for _, v := range vers {
				if !seen[v] {
					seen[v] = true
					uniq = append(uniq, v)
				}
			}
			sort.Slice(uniq, func(i, j int) bool {
				return compareVersions(uniq[i], uniq[j]) < 0
			})
			fp[path][hash] = uniq
		}
	}

	return fp
}

func fetchHash(client *http.Client, version, path string) (string, bool) {
	url := fmt.Sprintf("%s/%s/%s", svnTagsBase, version, path)
	resp, err := client.Get(url)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%x", md5.Sum(body)), true
}

func printStats(fp map[string]map[string][]string) {
	log.Println("Fingerprint stats:")
	total := 0
	for path, hashMap := range fp {
		versions := 0
		for _, v := range hashMap {
			versions += len(v)
		}
		total += versions
		log.Printf("  %s: %d distinct hashes, %d version mappings", path, len(hashMap), versions)
	}
	log.Printf("  Total: %d version mappings", total)
}
