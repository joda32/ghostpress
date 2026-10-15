# Ghostpress - Design Document

> A fast, portable, single-binary WordPress security auditor written in Go.
> Effectively a focused Go reimplementation of the core WPScan workflow, with an
> embedded, self-updating vulnerability database and zero runtime dependencies.

---

## 1. Overview

Ghostpress scans a target URL, confirms whether it runs WordPress, fingerprints
the core version, active theme, installed plugins and users, probes for a range
of "interesting" misconfigurations, correlates everything against an embedded
CVE database, and optionally runs a password attack against discovered users.

Results are emitted either as a colourised CLI report or as machine-readable
JSON.

Three binaries are produced from this repo, split across **two independent Go
modules**:

| Binary            | Module / package                     | Purpose                                                        |
|-------------------|--------------------------------------|----------------------------------------------------------------|
| `ghostpress`      | `ghostpress` - `main` (repo root)    | The scanner itself.                                            |
| `vulndb-gen`      | `ghostpress/tools` - `tools/vulndb-gen`      | Offline tool that builds `data/vulndb.json.gz` from the Wordfence Intelligence v3 feed + ExploitDB (optional GitHub PoCs). |
| `fingerprint-gen` | `ghostpress/tools` - `tools/fingerprint-gen` | Offline tool that builds `data/wp_fingerprints.json` by hashing per-release static files from the WordPress core SVN tags. |

The scanner lives in the root `ghostpress` module. The offline data generators
live in a **separate `ghostpress/tools` module** (`tools/`) with its own
`go.mod` and **no dependency on the scanner** - it reads the scanner's `data/`
directory from disk (`--data-dir`, default `../data`) and writes the regenerated
JSON back into it. This keeps the scanner module free of any build-tool surface;
`go build ./...` at the repo root builds only the scanner, and the generators are
built/run from `tools/` (e.g. `cd tools && go run ./vulndb-gen -o -`).

### Design goals

1. **Single static binary, no dependencies.** All wordlists, fingerprints and
   the vulnerability database are compiled in via `go:embed`. The tool runs from
   a copy with nothing else installed (Linux and Windows builds are shipped).
2. **Portability over feature parity.** It deliberately targets the most
   valuable subset of WPScan behaviour rather than cloning it wholesale.
3. **Fast and concurrent.** A bounded worker pool and batched bulk requests keep
   enumeration quick while staying polite via throttling.
4. **Offline vulnerability intelligence.** The CVE database ships embedded and
   can be refreshed with `ghostpress update` without rebuilding.
5. **Scriptable.** JSON output and a meaningful exit code make it CI/automation
   friendly.

### Non-goals

- Exploitation. Ghostpress reports vulnerabilities and links to PoCs/exploits;
  it does not weaponise them.
- A plugin/extension system or scripting engine.
- Crawling/spidering the whole site - probing is targeted at known WordPress
  paths and the homepage.

---

## 2. High-level architecture

```
                         ┌───────────────┐
  CLI flags (cobra)  ───▶│   main (root) │  parse flags, build ScanOptions,
                         │               │  wire output, handle signals,
                         │               │  run `update`/`version` subcommands
                         └───────┬───────┘
                                 │ ScanOptions + Formatter
                                 ▼
                         ┌───────────────┐
                         │   scanner     │  orchestration: ordered pipeline of
                         │               │  wp.* phases, stats, result assembly
                         └───┬───────┬───┘
            httpclient.Client│       │ wp.* functions
                             ▼       ▼
              ┌──────────────────┐ ┌──────────────────────────────┐
              │   httpclient     │ │            wp                 │
              │ bounded pool,    │ │ target / version / plugins /  │
              │ throttle, UA     │ │ themes / users / interesting /│
              │ rotation, bulk   │ │ attacks (detection logic)     │
              └────────┬─────────┘ └───────────────┬──────────────┘
                       │                           │
                       │                 lookups   ▼
                       │                 ┌──────────────────┐
                       │                 │     model        │  shared types,
                       │                 │                  │  version compare,
                       │                 └──────────────────┘  enum/opts
                       │                           │
                       ▼                           ▼
              ┌──────────────────┐        ┌──────────────────┐
              │     output       │        │      data        │  embedded
              │ CLI / JSON       │        │ wordlists +      │  assets +
              │ (Formatter)      │        │ vulndb + fprints │  local override
              └──────────────────┘        └──────────────────┘
```

### Package responsibilities

| Package      | Responsibility |
|--------------|----------------|
| `main`       | CLI surface (cobra), flag → `ScanOptions` translation, enumerate-string parsing, output wiring, signal handling, `version` and `update` subcommands, exit codes. |
| `scanner`    | The orchestrator. Owns the `httpclient.Client`, drives the fixed-order scan pipeline, collects stats, builds the final `ScanResult`, and pushes each phase to the `Formatter`. |
| `httpclient` | Thin HTTP layer: bounded concurrency (semaphore), throttling, UA rotation, custom headers/auth/proxy, redirect policy, TLS toggling, byte/response accounting, and batched bulk GET/HEAD. |
| `wp`         | All WordPress-specific detection logic, split by concern (target, version, plugins, themes, users, interesting findings, attacks). Each is a set of pure-ish functions taking a client + target. |
| `model`      | Shared data types (`ScanOptions`, `ScanResult`, `Plugin`, `Theme`, `User`, `Vulnerability`, …), detection-mode enum, version comparison, byte formatting. No I/O. |
| `output`     | The `Formatter` interface and its two implementations: ANSI CLI and JSON. |
| `data`       | `go:embed` of all static assets, line-parsing helpers, and the vulndb load path with a local-file override. |
| `tools/vulndb-gen` | Generator (separate `ghostpress/tools` module) that produces `data/vulndb.json.gz` from the Wordfence Intelligence v3 feed, enriched with ExploitDB (and optional GitHub PoC) references. |
| `tools/fingerprint-gen` | Generator (separate `ghostpress/tools` module) that produces `data/wp_fingerprints.json` by MD5-hashing tracked static files across WordPress releases (fetched per-file from core SVN tags). |

The dependency direction is strictly one-way: `main → scanner → {wp, output, httpclient, data} → model`. Nothing in `wp`/`model` imports `output` or `scanner`, which keeps the detection logic reusable and testable in isolation.

---

## 3. Scan pipeline

`scanner.Scanner.Run(ctx)` executes a deterministic, ordered pipeline. Order
matters because later phases depend on earlier results (e.g. the password attack
needs enumerated users; theme enumeration folds in the already-detected main
theme).

1. **Banner** - printed via the formatter (no-op for JSON).
2. **Target acquisition** (`wp.NewTarget`)
   - Normalises the URL (adds scheme/trailing slash), resolves the IP.
   - Fetches the homepage once and caches body + headers on the `Target`
     (reused by every passive finder, so passive detection costs no extra
     requests).
   - Detects the `wp-content` directory name from the homepage.
   - Runs WordPress detection; if negative and `--force` not set, the scan
     short-circuits with a "not WordPress" result.
   - Fetches a random 404 URL to capture a **soft-404 baseline** body for later
     false-positive suppression.
3. **Interesting findings** (`wp.FindInteresting`) - headers, XML-RPC, REST API,
   robots.txt, readme, debug log, wp-cron, registration, full-path disclosure,
   upload listing, multisite, search-replace-db, Duplicator logs.
4. **Version detection** (`wp.DetectVersion`) → vuln lookup.
5. **Main theme detection** (`wp.DetectMainTheme`) → vuln lookup.
6. **Enumeration** (only if any `--enumerate` option is active): plugins,
   themes, users, config backups, DB exports, TimThumbs, media - each gated by
   its own flag.
7. **Password attack** (`wp.RunPasswordAttack`) - only when `--passwords` is set
   **and** at least one user was enumerated.
8. **Finalisation** - record end time and client stats, emit `ScanFinished`.

If no enumeration flags are supplied, `main` defaults to enumerating plugins,
themes and users.

### Detection modes

A single `DetectionMode` (`passive` / `mixed` / `aggressive`, default `mixed`)
governs how intrusive every phase is. The convention is uniform across `wp`:

```go
if mode != model.ModeAggressive { /* passive finders (homepage-only, 0 extra requests) */ }
if mode != model.ModePassive   { /* aggressive finders (active probing)              */ }
```

- **Passive** - only parses the already-fetched homepage and response headers.
- **Aggressive** - only active probing (feeds, readme, fingerprint files, known
  plugin/theme locations, REST API, author brute-forcing).
- **Mixed** - both, with results merged and de-duplicated by the highest
  confidence.

`--stealthy` is sugar for `--random-user-agent` + passive mode.

### Confidence model

Every finding carries a `Confidence` (0-100) and a human-readable `FoundBy`
string tagged `(Passive)` / `(Aggressive)`. When the same entity is found by
multiple methods, the higher-confidence hit wins. Version detection keeps only
the single highest-confidence candidate and discards everything below a
threshold of 40.

---

## 4. HTTP client design

`httpclient.Client` wraps `net/http` with the behaviours a scanner needs:

- **Bounded concurrency** via a buffered channel used as a semaphore
  (`sem := make(chan struct{}, threads)`); every request acquires/releases a
  slot. Default 5 threads.
- **Throttling** - optional fixed sleep per request (held inside the semaphore
  slot).
- **User-Agent** - fixed string or random rotation from the embedded UA list.
- **Custom headers, cookie string, HTTP basic auth, proxy (HTTP/SOCKS)** -
  configured per client; auth/headers applied per request.
- **Redirect policy** - capped at `MaxRedirects`, falling back to
  `ErrUseLastResponse`.
- **TLS** - `--disable-tls-checks` flips `InsecureSkipVerify`.
- **Accounting** - atomic counters for requests done and bytes received,
  exposed via `GetStats()`.
- **Response cap** - bodies are read through `io.LimitReader` (10 MiB) to bound
  memory.

Request helpers: `Get`, `Head`, `Post`, `PostWithCookie` (forces no-redirect,
used by the login brute-forcer to read the 302/Set-Cookie), `HeadOrGet` (HEAD
with GET fallback on 405/400), and crucially `BulkGet`/`BulkHead`, which fan a
slice of URLs out across goroutines (still bounded by the shared semaphore) and
return index-aligned `BulkResult`s. Enumeration uses bulk requests in batches of
50 to keep plugin/theme/user sweeps fast.

---

## 5. Detection logic (`wp` package) in detail

### Target (`target.go`)
WordPress detection looks for `/wp-content/`, `/wp-includes/`, `wp-admin`, a
`generator` meta tag, an `X-Pingback: …xmlrpc.php` header, or a `wp-json` `Link`
header. The content directory is extracted from the first
`/<dir>/(plugins|themes)/` match so non-default `wp-content` layouts are handled.
Soft-404 detection compares a candidate response against the captured 404
baseline (exact-match and a ±5% body-length ratio) plus common error markers.

### Version (`version.go`)
- **Passive:** generator meta tag (conf 80), RSS/Atom generators (80),
  `?ver=` query params on wp assets (30).
- **Aggressive:** feed endpoints (90), `readme.html` (90), and **fingerprinting**
  - MD5-hashing known static files and voting versions from
  `wp_fingerprints.json`. Fingerprint confidence is evidence-weighted: 1 agreeing
  file → 60, 2 → 85, 3+ → 100, capped at 50 when the top vote is tied across
  versions (ambiguous). The DB is produced by `tools/fingerprint-gen`.
- The winner's branch (`major.minor`) is looked up in the embedded vulndb and
  version-filtered via `Vulnerability.AffectsVersion`.

### Plugins / Themes (`plugins.go`, `themes.go`)
- **Passive:** regex over the homepage for `/<content>/plugins/<slug>/` and
  theme `style.css` / directory references.
- **Aggressive:** bulk-request known slugs from the embedded popular lists;
  a 403 implies "present but protected" (conf 80), a 200 directory listing is a
  strong hit (conf 100), and a `readme.txt` with plugin markers is a weaker
  confirmation (70).
- **Version:** parsed from `readme.txt` `Stable tag:`, `changelog.txt`, or (for
  themes) the `style.css` header fields.
- Each discovered slug is correlated against the plugin/theme vuln maps.

### Users (`users.go`)
Passive: `/author/<name>/` links and `author-<name>` CSS classes. Aggressive:
the WP REST `wp/v2/users` endpoint (conf 100, paginated), the oEmbed endpoint,
author sitemaps, and `?author=<id>` redirect brute-forcing over a configurable
ID range. Results merge by username keeping the highest confidence.

### Media (`media.go`)
Passive: harvests `wp-content/uploads/…` URLs already present in the homepage
(conf 60). Aggressive: the REST `wp/v2/media` endpoint (conf 100, paginated,
captures `source_url` + title) and `?attachment_id=<id>` brute-forcing over a
configurable range (`--media-range`, default 50), resolving each attachment to
its upload URL via redirect `Location` (conf 90) or a body match (conf 70).
Results merge by URL keeping the highest confidence.

### Interesting findings (`interesting.go`)
Header inspection plus targeted probes for XML-RPC (`system.listMethods`, with
amplification/SSRF/credential-testing method call-outs), REST API exposure,
robots.txt, readme, `wp-content/debug.log`, wp-cron, open registration,
full-path disclosure via PHP errors, upload directory listing, multisite,
`searchreplacedb2.php`, and Duplicator installer logs.

### Attacks (`attacks.go`)
A `PasswordAttacker` interface with three implementations selected by
`--password-attack`:

- `wp-login` - form POST to `wp-login.php`, success detected via a 302 to
  `wp-admin`, a `wordpress_logged_in_` cookie, or dashboard markers.
- `xmlrpc` - `wp.getUsersBlogs` method call.
- `xmlrpc-multicall` - `system.multicall` wrapper (amplifies attempts per
  request; the generator understands fault-code responses).

The attack is **breadth-first** (each password against all users before moving
on), context-cancellable, and reads its wordlist from a file. This file also
holds the config-backup / DB-export / TimThumb checkers, which bulk-request
candidate paths and filter by status, content-type and body signatures
(e.g. `CREATE TABLE`/`INSERT INTO` for DB dumps).

---

## 6. Data model (`model` package)

`ScanResult` is the single aggregate that both formatters consume. Key types:

- `TargetInfo`, `WPVersion`, `Plugin`, `Theme`, `User`, `InterestingFinding`,
  `PasswordResult` - all JSON-tagged for machine output.
- `Vulnerability` + `Reference` + `VersionRange` - a reference has a `Type`
  (`cve`/`exploitdb`/`poc`/`url`/`wpvulndb`) and renders a canonical URL via
  `Reference.URL()`. `HasExploit()` drives the "public exploit available"
  highlighting. `AffectsVersion` uses the `Affected []VersionRange` list when
  present (each range has inclusive/exclusive `from`/`to` bounds, `*` =
  unbounded - mirroring the Wordfence feed), and falls back to the legacy
  `< fixed_in` semantics otherwise.
- `ScanOptions` / `EnumerateOptions` - the full flag surface, decoupled from
  cobra so `scanner` has no CLI dependency.

Two pure helpers live here: `CompareVersions` (dotted numeric comparison tolerant
of non-numeric suffixes, used by `AffectsVersion` and `VersionRange.Contains`)
and `FormatBytes`.

`ScanResult.Vulnerable()` returns true if any core/plugin/theme vuln or valid
credential was found; `main` maps that to **exit code 5** (vs 1 for a hard error,
0 otherwise) so CI can gate on it.

---

## 7. Output (`output` package)

A narrow `Formatter` interface is called once per scan phase, letting the scanner
stay oblivious to the output format:

- **`CLIFormatter`** - ANSI-coloured, severity-aware (CVSS + exploit presence →
  critical/high/medium/info palette), with an ASCII banner. Colour is
  auto-disabled when writing to a non-TTY or a file.
- **`JSONFormatter`** - accumulates each phase into a `ScanResult` and marshals
  the whole thing once at `ScanFinished`.

Writing to `-o <file>` forces no-colour and routes both formats to the file.

---

## 8. Embedded data & the vulnerability pipeline

The scanner embeds a set of static assets at build time; the data that feeds
them is produced by the generators in the separate `ghostpress/tools` module
(see §1). Those generators read and write the `data/` directory on disk via
`--data-dir` (default `../data`, i.e. the scanner module's `data/` when run from
`tools/`) and depend on nothing from the scanner module - they are a fully
standalone application.

### Embedded assets (`data`)
All compiled in with `go:embed`: `user_agents.txt`, `config_backups.txt`,
`db_exports.txt`, `timthumbs.txt`, `popular_plugins.txt`, `popular_themes.txt`,
`wp_fingerprints.json`, and **`vulndb.json.gz`**. The vuln DB is embedded
gzip-compressed (~2.6 MB vs ~26 MB raw) because it now holds ~45k entries;
`data.VulnDB()` decompresses it on first use. Text lists are parsed with a
shared `lines()` helper that trims and drops `#` comments.

### Three freshness tiers
The same `tools/vulndb-gen` output reaches the scanner three ways:

- **Embedded** - `data/vulndb.json.gz` compiled into the binary; refreshed in
  source only on tagged releases. The offline baseline.
- **`ghostpress update`** - pulls the daily-rebuilt DB from a GitHub Release
  asset into `~/.ghostpress/vulndb.json`. No rebuild needed.
- **Self-rebuild** - a user with their own Wordfence key runs `vulndb-gen` for
  the absolute latest data.

`data.VulnDB()` prefers `~/.ghostpress/vulndb.json` if present and non-trivial,
else the embedded copy (memoised with `sync.Once`); either source may be raw
JSON or gzip (`maybeGunzip` handles both). `data.VulnDB()` returns raw JSON, and
`wp` parses it **once** into a slug-keyed cache (`wp/vulndb.go`) - essential now
that enumeration can touch tens of thousands of entries.

### `update` subcommand
`ghostpress update --url <release-asset>` downloads the DB, optionally verifies a
sibling `<url>.sha256`, gunzips it, validates the JSON shape, counts entries, and
writes raw JSON to `~/.ghostpress/vulndb.json`. The default URL (a GitHub Release
`…/releases/latest/download/vulndb.json.gz`) is baked in via
`-ldflags "-X main.vulnDBURL=…"`.

### `vulndb-gen` (offline generator, `tools/` module)
Produces `vulndb.json[.gz]` from the **Wordfence Intelligence v3** feed - the
authoritative WordPress vulnerability source (core + plugins + themes), which
supplies the real directory **slug**, structured affected-version ranges, CVE,
CVSS and CWE. (This replaced an earlier NVD-based pipeline, which missed the bulk
of plugin/theme CVEs because NVD stopped adding the CPE data the old queries
depended on.)

1. **Fetch** the production feed (needs a Wordfence key via `--wf-api-key` /
   `WORDFENCE_API_KEY`; `--feed-file` processes a pre-downloaded feed), with
   429 backoff. ~42k records.
2. **Transform** each record per `software` entry: route to `wordpress` (single
   `"wordpress"` bucket), `plugins[slug]`, or `themes[slug]`; carry title, CVE,
   CVSS, CWE→type, references, and the version ranges + first patched version.
   The slug comes from Wordfence, never the CNA product name.
3. **Enrich** by CVE id: ExploitDB (CVE→EDB from the WordPress rows of the public
   CSV, on by default) and optional GitHub PoC references (`--github-pocs`, off
   by default - one request per CVE is impractical at 42k).
4. **Attribution** (license requirement): the Defiant copyright + license go in
   `_meta.license`, and every vuln keeps its Wordfence record hyperlink in
   `references`.
5. **Shape** into `{wordpress, plugins, themes, _meta}`, sorted by CVSS
   descending; gzip when the output path ends in `.gz`.

Core vulns are stored in one `"wordpress"` bucket with absolute ranges;
`lookupWPVulns` scans them with the range-aware `AffectsVersion` (and still reads
legacy branch-keyed, `fixed_in`-style data for backward compatibility).

### Daily automation (GitHub Actions)
`.github/workflows/update-vulndb.yml` runs daily (and on demand), builds the DB
with `WORDFENCE_API_KEY` from a repo secret, sanity-checks + checksums it, and
replaces the `vulndb-latest` release assets (`vulndb.json.gz` +
`.sha256`) that `ghostpress update` pulls. The generator only writes on success
and the job only publishes if generation succeeds, so a feed outage leaves the
previous asset intact. The key never touches the repo or logs.

> **Licensing:** the per-record Defiant grant permits redistribution with
> attribution (preserved as above). Bulk publication of the full feed is also
> subject to the Wordfence Intelligence Terms & Conditions - confirm those before
> making the dataset repo public. See `data/ATTRIBUTION.md`.

### `fingerprint-gen` (version fingerprint generator, `tools/` module)
Produces `<data-dir>/wp_fingerprints.json`, the `path → md5 → [versions]` map
that drives aggressive version fingerprinting:

1. **Paths** - taken from the keys of the existing `wp_fingerprints.json` on
   disk (single source of truth for which files matter), falling back to a
   built-in default list.
2. **Versions** - an explicit `--versions` list, or auto-listed from the core
   SVN tag index filtered by `--min`.
3. **Fetch & hash** - for each (version, path), GET
   `https://core.svn.wordpress.org/tags/<version>/<path>` (only the handful of
   tracked files per release, not the full zip), MD5 the body, and record the
   version under that hash. A bounded worker pool parallelises downloads.
4. **Shape** - dedup and version-sort each hash's list, emit indented JSON.

The shipped DB covers WordPress 5.0+ (≈396 releases). The most discriminating
file is `block-library/style.min.css`; `jquery.js` barely changes between
releases, which is exactly why detection votes across multiple files rather than
trusting any single match.

---

## 9. Test lab

`lab/docker-compose.yml` + `lab/setup.sh` stand up a disposable WordPress 6.8
(PHP 8.2) + MySQL 5.7 target on `localhost:8888`, seeded via WP-CLI with weak
users (admin/editor/author/subscriber) and author-attributed posts - a safe,
reproducible target for exercising enumeration and the password attack.

---

## 10. Build & distribution

- Two modules: `ghostpress` (the scanner; Go 1.22, only direct dependency
  `spf13/cobra`) and `ghostpress/tools` (the generators; Go 1.22, standard
  library only, no dependencies). `go build ./...` at the repo root builds only
  the scanner; the generators build from `tools/`.
- Everything the scanner needs at runtime is embedded, so distribution is a
  single file.
- **Release automation** (`.github/workflows/release.yml`): triggered by a
  `vX.Y.Z` tag (or manual dispatch), it refreshes the embedded DB from Wordfence
  (when `WORDFENCE_API_KEY` is set, else embeds the committed copy), cross-compiles
  static binaries (`CGO_ENABLED=0`, `-trimpath`, `-s -w`) for linux/amd64,
  linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64, archives each with
  `ATTRIBUTION.md`, writes `sha256sums.txt`, and publishes a GitHub release.
- Version string is injected at build via `-ldflags "-X main.version=…"`
  (defaults to `dev`); the update URL via `-X main.vulnDBURL=…`, pointed at the
  rolling `vulndb-latest` data release so `ghostpress update` always gets the
  daily-refreshed DB independent of binary version.

---

## 11. Review notes - gaps & inconsistencies

Observations from reading the current tree. None are crashes; they are places
where behaviour diverges from apparent intent and would be the first candidates
for cleanup.

1. **`DataSent` is never incremented.** `httpclient` tracks `RequestsDone` and
   `DataReceived` but never adds to `DataSent`, so `ScanResult.DataSent` is
   always 0 (the CLI happens not to print it; JSON reports 0).
2. ~~**`CookieString` is accepted but unused.**~~ **Fixed.** The client now
   stores the cookie string and attaches it as a `Cookie` header on every
   request (`do`), merging it with the per-call login test cookie in
   `PostWithCookie`.
3. ~~**Fingerprint DB is effectively empty.**~~ **Fixed.** Added
   `tools/fingerprint-gen`, which populates `data/wp_fingerprints.json` from the
   WordPress core SVN tags; the shipped DB now covers WP 5.0+ (≈396 releases,
   ~28 KB). Fingerprint confidence is no longer a flat 100 - it is weighted by
   how many files agree and capped at 50 on an ambiguous (tied) top vote.
4. ~~**`--enumerate m` (medias) is parsed but not handled.**~~ **Fixed.** Added
   `wp.EnumerateMedia` (REST `wp/v2/media` + `?attachment_id=N` brute, plus
   passive homepage harvest), a `model.Media` type, a `Formatter.Media` method
   (CLI + JSON), a `--media-range` flag, and the `runEnumeration` branch.
5. ~~**Custom plugin/theme slug files are not wired up.**~~ **Fixed.** New
   `--plugins-list` / `--themes-list` flags bind `ScanOptions.PluginsSlugs` /
   `ThemesSlugs`; `pluginSlugsToCheck` / `themeSlugsToCheck` now read the file
   (shared `loadSlugFile` helper, falling back to the embedded popular list),
   and the slug file is threaded through `EnumerateThemes`.
6. ~~**`ProxyAuth` has no flag.**~~ **Fixed.** New `--proxy-auth user:pass` flag
   binds `ScanOptions.ProxyAuth`, which `scanner` now passes into
   `httpclient.Options` (the client already honoured it).
7. **Dead / unused exported helpers in `wp`.** `LoginErrorUsers`,
   `CheckPluginDirectoryListing`, `CheckPluginErrorLog`, and `hasWPContent` are
   defined but never called from the pipeline.
8. **Redundant mode re-derivation.** `scanner.Run` recomputes
   `mode = ModePassive` for stealthy even though `main.PreRunE` already forced
   passive mode into `opts.DetectionMode`.
9. **`HeadOrGet` is unused**, and `BulkHead` has no caller - the enumeration
   paths all use `BulkGet`.

### Natural next steps
- ~~Populate `wp_fingerprints.json` (generate hashes per release).~~ Done via
  `tools/fingerprint-gen` - see note 3 above. Could be extended with more
  discriminating files to resolve point-release ties.
- ~~Wire the orphaned flags (`--cookie-string`, proxy auth, custom slug files).~~
  Done - see notes 2, 5, 6 above.
- ~~Implement media enumeration or drop the `m` option.~~ Done - see note 4 above.
- Add unit tests around the pure logic (`CompareVersions`, `AffectsVersion`,
  classification/title helpers in `vulndb-gen`, soft-404 heuristics) - these are
  dependency-free and the highest-leverage things to pin down.
- Track `DataSent` for honest bandwidth accounting.
```
