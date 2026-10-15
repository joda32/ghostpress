package wp

import (
	"encoding/json"
	"sync"

	"ghostpress/data"
	"ghostpress/model"
)

// The vulnerability database can hold tens of thousands of entries, so it is
// parsed exactly once and cached. Previously each plugin/theme/version lookup
// re-unmarshalled the entire DB, which is O(DB size) per enumerated item.
type vulnDatabase struct {
	WordPress map[string][]model.Vulnerability `json:"wordpress"`
	Plugins   map[string][]model.Vulnerability `json:"plugins"`
	Themes    map[string][]model.Vulnerability `json:"themes"`
}

var (
	vulnDBOnce   sync.Once
	vulnDBParsed vulnDatabase
)

func vulnDB() *vulnDatabase {
	vulnDBOnce.Do(func() {
		_ = json.Unmarshal(data.VulnDB(), &vulnDBParsed)
	})
	return &vulnDBParsed
}

// VulnDBCount reports how many advisories the embedded database holds, summed
// across WordPress core, plugins, and themes. It's used for the startup banner;
// it shares the same cached parse the scan uses, so it adds no extra work.
func VulnDBCount() int {
	db := vulnDB()
	n := 0
	for _, v := range db.WordPress {
		n += len(v)
	}
	for _, v := range db.Plugins {
		n += len(v)
	}
	for _, v := range db.Themes {
		n += len(v)
	}
	return n
}
