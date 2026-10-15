# Data attribution

## Vulnerability data - Wordfence Intelligence (Defiant Inc.)

`vulndb.json` / `vulndb.json.gz` is generated from the **Wordfence Intelligence
v3 Vulnerability Data Feed**.

> Copyright 2012-present Defiant Inc.
>
> Defiant grants a perpetual, worldwide, non-exclusive, no-charge, royalty-free,
> irrevocable copyright license to reproduce, prepare derivative works of,
> publicly display, publicly perform, sublicense, and distribute this software
> vulnerability information, **provided that you include a hyperlink to each
> vulnerability record and reproduce Defiant's copyright designation and this
> license in any such copy.**
>
> License: <https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/>

To satisfy this license, the generated database:

- stores the full Defiant copyright notice and license text in its `_meta.license` block, and
- preserves every vulnerability's Wordfence record hyperlink
  (`https://www.wordfence.com/threat-intel/vulnerabilities/id/<id>`) in its `references`.

Do not strip either when redistributing the database.

> **Note on redistribution:** the per-record copyright license above permits
> redistribution with attribution. Bulk redistribution / use of the feed is also
> governed by the Wordfence Intelligence Terms & Conditions (link above). Confirm
> the current Terms permit your intended distribution before publishing the full
> database publicly.

## Enrichment sources

- **ExploitDB** - CVE↔exploit-id mappings (facts), from the public Exploit-Database `files_exploits.csv`.
- **GitHub PoC references** (optional) - public repository URLs from `nomi-sec/PoC-in-GitHub`.
- Legacy builds also used **NVD / NIST** CVE data (public domain).
