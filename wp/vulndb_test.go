package wp

import "testing"

// These exercise the full embedded path: gzip-decompress, parse-once cache, and
// range-based AffectsVersion matching against the real shipped database.

func TestLookupPluginVulnsRanges(t *testing.T) {
	// wpappninja (WPMobile.App) has ranges like *-11.82; an install at 11.82 is
	// vulnerable, one above every patched range is not.
	if got := lookupPluginVulns("wpappninja", "11.82"); len(got) == 0 {
		t.Fatalf("expected vulns for wpappninja 11.82, got 0")
	}
	if got := lookupPluginVulns("wpappninja", "999.0"); len(got) != 0 {
		t.Fatalf("expected no vulns for wpappninja 999.0, got %d", len(got))
	}
}

func TestLookupPluginVulnsLowerBound(t *testing.T) {
	// peprodev-ups entries are bounded 1.9.1 .. 7.5.2 inclusive; 1.0 is below
	// the lower bound and must not match those ranged entries.
	for _, v := range lookupPluginVulns("peprodev-ups", "1.0") {
		for _, r := range v.Affected {
			if r.FromVersion == "1.9.1" {
				t.Fatalf("1.0 should be below the 1.9.1 lower bound: %q", v.Title)
			}
		}
	}
	if got := lookupPluginVulns("peprodev-ups", "7.5.2"); len(got) == 0 {
		t.Fatalf("expected vulns for peprodev-ups 7.5.2, got 0")
	}
}

func TestVulnDBPopulated(t *testing.T) {
	db := vulnDB()
	if len(db.Plugins) < 1000 {
		t.Fatalf("expected a large plugin DB, got %d slugs", len(db.Plugins))
	}
}
