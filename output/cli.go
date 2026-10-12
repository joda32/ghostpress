package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ghostpress/model"
)

type palette struct {
	reset, bold, dim       string
	critical, high, medium string
	info, name, method     string
}

func newPalette(colour bool) palette {
	if !colour {
		return palette{}
	}
	return palette{
		reset:    "\x1b[0m",
		bold:     "\x1b[1m",
		dim:      "\x1b[2m",
		critical: "\x1b[31m",   // red
		high:     "\x1b[33m",   // amber
		medium:   "\x1b[32m",   // green
		info:     "\x1b[90m",   // grey
		name:     "\x1b[1;36m", // bold cyan
		method:   "\x1b[35m",   // magenta
	}
}

func (p palette) forSeverity(cvss float64, hasExploit bool) string {
	if hasExploit || cvss >= 9.0 {
		return p.critical
	}
	if cvss >= 7.0 {
		return p.high
	}
	if cvss >= 4.0 {
		return p.medium
	}
	return p.info
}

type CLIFormatter struct {
	w               io.Writer
	p               palette
	showUnconfirmed bool
}

func NewCLI(noColor bool, output *os.File, showUnconfirmed bool) *CLIFormatter {
	w := io.Writer(os.Stdout)
	if output != nil {
		w = output
	}
	colour := !noColor
	if noColor {
		colour = false
	} else if f, ok := w.(*os.File); ok {
		info, err := f.Stat()
		if err == nil {
			colour = info.Mode()&os.ModeCharDevice != 0
		}
	}
	return &CLIFormatter{w: w, p: newPalette(colour), showUnconfirmed: showUnconfirmed}
}

func (f *CLIFormatter) pr(format string, args ...any) {
	fmt.Fprintf(f.w, format, args...)
}

func (f *CLIFormatter) heading(colour, text string, count int) {
	h := fmt.Sprintf("%s (%d)", text, count)
	rule := strings.Repeat("─", max(0, 70-len(h)))
	f.pr("\n%s%s%s%s %s%s%s\n", f.p.bold, colour, h, f.p.reset, f.p.dim, rule, f.p.reset)
}

func (f *CLIFormatter) section(text string) {
	rule := strings.Repeat("─", max(0, 70-len(text)))
	f.pr("\n%s%s%s%s %s%s%s\n", f.p.bold, f.p.info, text, f.p.reset, f.p.dim, rule, f.p.reset)
}

func (f *CLIFormatter) Banner() {
	banner := `
                ░██████╗░██████╗░
                ██╔════╝░██╔══██╗
                ██║░░██╗░██████╔╝   %s%sghostpress%s
                ██║░░╚██╗██╔═══╝    %sWordPress Security Auditor%s
                ╚██████╔╝██║
                ░╚═════╝░╚═╝
`
	f.pr(banner, f.p.bold, f.p.name, f.p.reset, f.p.dim, f.p.reset)
}

func (f *CLIFormatter) ScanStarted(target model.TargetInfo) {
	f.section("Target")
	f.pr("  %s%-12s%s %s\n", f.p.method, "URL", f.p.reset, target.URL)
	if target.EffectiveURL != target.URL {
		f.pr("  %s%-12s%s %s\n", f.p.method, "Effective", f.p.reset, target.EffectiveURL)
	}
	if target.IP != "" {
		f.pr("  %s%-12s%s %s\n", f.p.method, "IP", f.p.reset, target.IP)
	}
	if target.Server != "" {
		f.pr("  %s%-12s%s %s\n", f.p.method, "Server", f.p.reset, target.Server)
	}
	if !target.WordPressFound {
		f.pr("\n  %s%sWordPress not detected — use --force to scan anyway%s\n", f.p.bold, f.p.high, f.p.reset)
	}
}

func (f *CLIFormatter) InterestingFindings(findings []model.InterestingFinding) {
	if len(findings) == 0 {
		return
	}
	f.heading(f.p.medium, "Interesting Findings", len(findings))
	for _, finding := range findings {
		f.pr("  %s%s%s\n", f.p.name, finding.Description, f.p.reset)
		f.pr("      %s%-7s%s %s\n", f.p.method, "URL", f.p.reset, finding.URL)
		f.pr("      %s%-7s%s %s\n", f.p.method, "Found", f.p.reset, finding.FoundBy)
		for _, entry := range finding.InterestingEntries {
			f.pr("      %s→%s %s\n", f.p.dim, f.p.reset, entry)
		}
		for _, ref := range finding.References {
			f.pr("      %s→%s %s\n", f.p.dim, f.p.reset, ref.URL())
		}
	}
}

func (f *CLIFormatter) Version(version *model.WPVersion) {
	if version == nil {
		f.pr("\n%sWordPress version not detected.%s\n", f.p.dim, f.p.reset)
		return
	}

	colour := f.p.medium
	if len(version.Vulnerabilities) > 0 {
		colour = f.p.critical
	}

	label := "Version"
	if len(version.Vulnerabilities) > 0 {
		label = fmt.Sprintf("Version — %d vulnerabilities", len(version.Vulnerabilities))
	}
	f.heading(colour, label, 1)
	f.pr("  %sWordPress %s%s\n", f.p.name, version.Number, f.p.reset)
	f.pr("      %s%-7s%s %s\n", f.p.method, "Found", f.p.reset, version.FoundBy)
	for _, entry := range version.InterestingEntries {
		f.pr("      %s→%s %s\n", f.p.dim, f.p.reset, entry)
	}
	f.printVulns(version.Vulnerabilities)
}

func (f *CLIFormatter) MainTheme(theme *model.Theme) {
	if theme == nil {
		return
	}

	colour := f.p.info
	if len(theme.Vulnerabilities) > 0 {
		colour = f.p.high
	}

	label := "Active Theme"
	if len(theme.Vulnerabilities) > 0 {
		label = fmt.Sprintf("Active Theme — %d vulnerabilities", len(theme.Vulnerabilities))
	}
	f.heading(colour, label, 1)

	ver := theme.Version
	if ver == "" {
		ver = "unknown"
	}
	f.pr("  %s%s%s  %s%s%s\n", f.p.name, theme.Slug, f.p.reset, f.p.dim, ver, f.p.reset)
	if theme.StyleName != "" {
		f.pr("      %s%-7s%s %s\n", f.p.method, "Name", f.p.reset, theme.StyleName)
	}
	if theme.Author != "" {
		f.pr("      %s%-7s%s %s\n", f.p.method, "Author", f.p.reset, theme.Author)
	}
	f.pr("      %s%-7s%s %s\n", f.p.method, "Found", f.p.reset, theme.FoundBy)
	if theme.VersionBlocked {
		f.unconfirmed(theme.KnownVulnCount, theme.UnconfirmedVulns)
	} else {
		f.printVulns(theme.Vulnerabilities)
	}
}

// unconfirmed renders the note for a component whose version could not be
// determined. By default it prints only the count of known vulnerabilities;
// with --show-unconfirmed it prints a warning and lists those vulnerabilities,
// which are known for the component across all versions and may not apply to the
// version actually installed.
func (f *CLIFormatter) unconfirmed(knownCount int, vulns []model.Vulnerability) {
	if f.showUnconfirmed {
		f.pr("      %s%-7s%s %s⚠ --show-unconfirmed: version could not be detected — the %d vulnerabilities below are known for this component across ALL versions and may NOT apply to the installed version%s\n",
			f.p.method, "Note", f.p.reset, f.p.high, knownCount, f.p.reset)
		f.printVulns(vulns)
		return
	}
	f.pr("      %s%-7s%s %s%d known vulnerabilities not confirmed (version undetermined)%s",
		f.p.method, "Note", f.p.reset, f.p.high, knownCount, f.p.reset)
	if knownCount > 0 {
		f.pr(" %s(re-run with --show-unconfirmed to list them)%s", f.p.dim, f.p.reset)
	}
	f.pr("\n")
}

func (f *CLIFormatter) Plugins(plugins []model.Plugin) {
	if len(plugins) == 0 {
		return
	}

	vulnCount := 0
	for _, p := range plugins {
		vulnCount += len(p.Vulnerabilities)
	}

	colour := f.p.medium
	label := "Plugins"
	if vulnCount > 0 {
		colour = f.p.high
		label = fmt.Sprintf("Plugins — %d vulnerabilities", vulnCount)
	}
	f.heading(colour, label, len(plugins))

	for _, p := range plugins {
		ver := p.Version
		if ver == "" {
			ver = "unknown"
			if p.VersionBlocked {
				ver = "unknown (unconfirmed)"
			}
		}
		f.pr("  %s%s%s  %s%s%s\n", f.p.name, p.Slug, f.p.reset, f.p.dim, ver, f.p.reset)
		f.pr("      %s%-7s%s %s\n", f.p.method, "Found", f.p.reset, p.FoundBy)
		if p.DirectoryListing {
			f.pr("      %s%-7s%s %s%sdirectory listing enabled%s\n", f.p.method, "Note", f.p.reset, f.p.bold, f.p.high, f.p.reset)
		}
		for _, entry := range p.InterestingEntries {
			f.pr("      %s→%s %s\n", f.p.dim, f.p.reset, entry)
		}
		if p.VersionBlocked {
			f.unconfirmed(p.KnownVulnCount, p.UnconfirmedVulns)
		} else {
			f.printVulns(p.Vulnerabilities)
		}
	}
}

func (f *CLIFormatter) Themes(themes []model.Theme) {
	if len(themes) == 0 {
		return
	}

	vulnCount := 0
	for _, t := range themes {
		vulnCount += len(t.Vulnerabilities)
	}

	colour := f.p.medium
	label := "Themes"
	if vulnCount > 0 {
		colour = f.p.high
		label = fmt.Sprintf("Themes — %d vulnerabilities", vulnCount)
	}
	f.heading(colour, label, len(themes))

	for _, t := range themes {
		ver := t.Version
		if ver == "" {
			ver = "unknown"
			if t.VersionBlocked {
				ver = "unknown (unconfirmed)"
			}
		}
		f.pr("  %s%s%s  %s%s%s\n", f.p.name, t.Slug, f.p.reset, f.p.dim, ver, f.p.reset)
		f.pr("      %s%-7s%s %s\n", f.p.method, "Found", f.p.reset, t.FoundBy)
		if t.VersionBlocked {
			f.unconfirmed(t.KnownVulnCount, t.UnconfirmedVulns)
		} else {
			f.printVulns(t.Vulnerabilities)
		}
	}
}

func (f *CLIFormatter) Users(users []model.User) {
	if len(users) == 0 {
		return
	}

	f.heading(f.p.high, "Users", len(users))
	for _, u := range users {
		idStr := ""
		if u.ID > 0 {
			idStr = fmt.Sprintf("  %sID:%d%s", f.p.dim, u.ID, f.p.reset)
		}
		f.pr("  %s%s%s%s\n", f.p.name, u.Username, f.p.reset, idStr)
		f.pr("      %s%-7s%s %s\n", f.p.method, "Found", f.p.reset, u.FoundBy)
	}
}

func (f *CLIFormatter) ConfigBackups(backups []string) {
	if len(backups) == 0 {
		return
	}
	f.heading(f.p.critical, "Config Backups", len(backups))
	for _, b := range backups {
		f.pr("  %s%s%s\n", f.p.critical, b, f.p.reset)
	}
}

func (f *CLIFormatter) DBExports(exports []string) {
	if len(exports) == 0 {
		return
	}
	f.heading(f.p.critical, "Database Exports", len(exports))
	for _, e := range exports {
		f.pr("  %s%s%s\n", f.p.critical, e, f.p.reset)
	}
}

func (f *CLIFormatter) TimThumbs(paths []string) {
	if len(paths) == 0 {
		return
	}
	f.heading(f.p.high, "TimThumbs", len(paths))
	for _, p := range paths {
		f.pr("  %s%s%s\n", f.p.high, p, f.p.reset)
	}
}

func (f *CLIFormatter) Media(media []model.Media) {
	if len(media) == 0 {
		return
	}
	f.heading(f.p.medium, "Media", len(media))
	for _, m := range media {
		f.pr("  %s%s%s\n", f.p.name, m.URL, f.p.reset)
		if m.Title != "" {
			f.pr("      %s%-7s%s %s\n", f.p.method, "Title", f.p.reset, m.Title)
		}
		f.pr("      %s%-7s%s %s\n", f.p.method, "Found", f.p.reset, m.FoundBy)
	}
}

func (f *CLIFormatter) PasswordResults(results []model.PasswordResult) {
	if len(results) == 0 {
		return
	}
	f.heading(f.p.critical, "Valid Credentials", len(results))
	for _, r := range results {
		f.pr("  %s%s%s  %s%s%s\n",
			f.p.name, r.Username, f.p.reset,
			f.p.critical, r.Password, f.p.reset)
	}
}

func (f *CLIFormatter) ScanFinished(result *model.ScanResult) {
	duration := result.EndTime.Sub(result.StartTime).Round(time.Millisecond)

	vulnCount := 0
	exploitCount := 0
	if result.Version != nil {
		vulnCount += len(result.Version.Vulnerabilities)
		for _, v := range result.Version.Vulnerabilities {
			if v.HasExploit() {
				exploitCount++
			}
		}
	}
	for _, p := range result.Plugins {
		vulnCount += len(p.Vulnerabilities)
		for _, v := range p.Vulnerabilities {
			if v.HasExploit() {
				exploitCount++
			}
		}
	}
	for _, t := range result.Themes {
		vulnCount += len(t.Vulnerabilities)
		for _, v := range t.Vulnerabilities {
			if v.HasExploit() {
				exploitCount++
			}
		}
	}

	f.pr("\n")

	if vulnCount > 0 || len(result.PasswordResults) > 0 {
		parts := []string{}
		if vulnCount > 0 {
			s := fmt.Sprintf("%d vulnerabilities", vulnCount)
			if exploitCount > 0 {
				s += fmt.Sprintf(" (%d with public exploits)", exploitCount)
			}
			parts = append(parts, s)
		}
		if len(result.PasswordResults) > 0 {
			parts = append(parts, fmt.Sprintf("%d valid credentials", len(result.PasswordResults)))
		}
		f.pr("%s%s%s%s\n", f.p.bold, f.p.critical, strings.Join(parts, ", "), f.p.reset)
	} else {
		f.pr("%sNo vulnerabilities identified.%s\n", f.p.bold, f.p.reset)
	}

	if result.RateLimited > 0 || result.Forbidden > 0 {
		f.pr("%s%s⚠ interference detected: %d rate-limited (429/503), %d forbidden (403) — the target is likely behind a WAF; some version detection was blocked and results may be incomplete%s\n",
			f.p.bold, f.p.high, result.RateLimited, result.Forbidden, f.p.reset)
	}

	unconfirmed := 0
	if result.MainTheme != nil {
		unconfirmed += result.MainTheme.KnownVulnCount
	}
	for _, p := range result.Plugins {
		unconfirmed += p.KnownVulnCount
	}
	for _, t := range result.Themes {
		unconfirmed += t.KnownVulnCount
	}
	if unconfirmed > 0 {
		hint := ""
		if !f.showUnconfirmed {
			hint = " — re-run with --show-unconfirmed to list them"
		}
		f.pr("%s%s⚠ %d additional vulnerabilities are known for components whose version could not be confirmed (not counted above)%s%s\n",
			f.p.bold, f.p.high, unconfirmed, hint, f.p.reset)
	}

	f.pr("%s%d requests, %s received, %s%s\n",
		f.p.dim, result.RequestsDone, model.FormatBytes(result.DataReceived), duration, f.p.reset)
}

func (f *CLIFormatter) Error(msg string) {
	f.pr("%s%serror:%s %s\n", f.p.bold, f.p.critical, f.p.reset, msg)
}

func (f *CLIFormatter) printVulns(vulns []model.Vulnerability) {
	if len(vulns) == 0 {
		return
	}
	for _, v := range vulns {
		sev := f.p.forSeverity(v.CVSS, v.HasExploit())

		title := v.Title
		if len(title) > 120 {
			if idx := strings.LastIndex(title[:120], " "); idx > 0 {
				title = title[:idx] + "…"
			}
		}
		f.pr("      %s●%s %s%s%s\n", sev, f.p.reset, sev, title, f.p.reset)

		if v.HasExploit() {
			f.pr("        %s%s⚡ PUBLIC EXPLOIT AVAILABLE%s\n", f.p.bold, f.p.critical, f.p.reset)
		}

		meta := []string{}
		if v.Type != "" {
			meta = append(meta, v.Type)
		}
		if v.CVSS > 0 {
			meta = append(meta, fmt.Sprintf("CVSS %.1f", v.CVSS))
		}
		if v.FixedIn != "" {
			meta = append(meta, "fixed in "+v.FixedIn)
		}
		if len(meta) > 0 {
			f.pr("        %s%s%s\n", f.p.dim, strings.Join(meta, " · "), f.p.reset)
		}

		for _, ref := range v.References {
			label := "ref"
			switch ref.Type {
			case "exploitdb":
				label = "exploit"
			case "poc":
				label = "poc"
			}
			f.pr("        %s%s%s %s\n", f.p.method, label, f.p.reset, ref.URL())
		}
	}
}
