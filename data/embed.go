package data

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed user_agents.txt
var userAgentsRaw string

//go:embed config_backups.txt
var configBackupsRaw string

//go:embed db_exports.txt
var dbExportsRaw string

//go:embed timthumbs.txt
var timthumbsRaw string

//go:embed popular_plugins.txt
var popularPluginsRaw string

//go:embed popular_themes.txt
var popularThemesRaw string

//go:embed vulndb.json.gz
var embeddedVulnDBGz []byte

//go:embed wp_fingerprints.json
var embeddedFingerprints []byte

//go:embed signatures.json
var embeddedSignatures []byte

var _ embed.FS

var (
	vulnDBOnce   sync.Once
	vulnDBCached []byte

	signaturesOnce     sync.Once
	signaturesCached   []byte
	signaturesOverride string

	fingerprintsOnce     sync.Once
	fingerprintsCached   []byte
	fingerprintsOverride string
)

// VulnDB returns the decompressed vulnerability database JSON. It prefers a
// local override at ~/.ghostpress/vulndb.json, otherwise the embedded copy.
// Either source may be gzip-compressed or raw JSON; both are handled.
func VulnDB() []byte {
	vulnDBOnce.Do(func() {
		if p := VulnDBLocalPath(); p != "" {
			if d, err := os.ReadFile(p); err == nil && len(d) > 2 {
				vulnDBCached = maybeGunzip(d)
				return
			}
		}
		vulnDBCached = maybeGunzip(embeddedVulnDBGz)
	})
	return vulnDBCached
}

// maybeGunzip decompresses b when it carries the gzip magic bytes, otherwise
// returns it unchanged.
func maybeGunzip(b []byte) []byte {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return b
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return b
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return b
	}
	return out
}

func VulnDBLocalPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ghostpress", "vulndb.json")
}

// SetSignaturesOverride makes Signatures() prefer the given file (an ad-hoc
// --signatures path) over the local and embedded copies. Call it before the
// first call to Signatures().
func SetSignaturesOverride(path string) { signaturesOverride = path }

// Signatures returns the raw WAF/misconfiguration signatures JSON. Precedence:
// the --signatures override file, then a local copy at ~/.ghostpress/signatures.json,
// then the embedded default. Any source may be gzip-compressed or raw JSON. This
// is what lets signatures change without rebuilding the binary.
func Signatures() []byte {
	signaturesOnce.Do(func() {
		for _, p := range []string{signaturesOverride, SignaturesLocalPath()} {
			if p == "" {
				continue
			}
			if d, err := os.ReadFile(p); err == nil && len(d) > 2 {
				signaturesCached = maybeGunzip(d)
				return
			}
		}
		signaturesCached = maybeGunzip(embeddedSignatures)
	})
	return signaturesCached
}

func SignaturesLocalPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ghostpress", "signatures.json")
}

// SetFingerprintsOverride makes WPFingerprints() prefer the given file (an ad-hoc
// --fingerprints path) over the local and embedded copies. Call it before the
// first call to WPFingerprints().
func SetFingerprintsOverride(path string) { fingerprintsOverride = path }

// WPFingerprints returns the raw WordPress core version-fingerprint JSON.
// Precedence: the --fingerprints override, then a local copy at
// ~/.ghostpress/wp_fingerprints.json, then the embedded default. Any source may
// be gzip-compressed or raw JSON. This is what lets the fingerprint DB be
// refreshed for newly released WordPress versions without rebuilding the binary.
func WPFingerprints() []byte {
	fingerprintsOnce.Do(func() {
		for _, p := range []string{fingerprintsOverride, FingerprintsLocalPath()} {
			if p == "" {
				continue
			}
			if d, err := os.ReadFile(p); err == nil && len(d) > 2 {
				fingerprintsCached = maybeGunzip(d)
				return
			}
		}
		fingerprintsCached = maybeGunzip(embeddedFingerprints)
	})
	return fingerprintsCached
}

func FingerprintsLocalPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ghostpress", "wp_fingerprints.json")
}

func lines(raw string) []string {
	var result []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result
}

func UserAgents() []string     { return lines(userAgentsRaw) }
func ConfigBackups() []string  { return lines(configBackupsRaw) }
func DBExports() []string      { return lines(dbExportsRaw) }
func TimThumbs() []string      { return lines(timthumbsRaw) }
func PopularPlugins() []string { return lines(popularPluginsRaw) }
func PopularThemes() []string  { return lines(popularThemesRaw) }
