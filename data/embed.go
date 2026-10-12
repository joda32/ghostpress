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
var WPFingerprintsRaw []byte

var _ embed.FS

var (
	vulnDBOnce   sync.Once
	vulnDBCached []byte
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
