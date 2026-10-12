package wp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"ghostpress/httpclient"
	"ghostpress/model"
)

func FindInteresting(ctx context.Context, client *httpclient.Client, target *Target, mode model.DetectionMode) []model.InterestingFinding {
	var findings []model.InterestingFinding

	findings = append(findings, checkHeaders(target)...)

	if mode != model.ModeAggressive {
		findings = append(findings, passiveInteresting(target)...)
	}

	if mode != model.ModePassive {
		findings = append(findings, aggressiveInteresting(ctx, client, target)...)
	}

	return findings
}

func checkHeaders(target *Target) []model.InterestingFinding {
	var findings []model.InterestingFinding

	interestingHeaders := []string{
		"Server", "X-Powered-By", "X-Pingback", "X-Redirect-By",
		"X-Generator", "X-Mod-Pagespeed", "X-Page-Speed",
		"Strict-Transport-Security", "X-Frame-Options",
		"Content-Security-Policy", "X-Content-Type-Options",
	}

	var entries []string
	for _, h := range interestingHeaders {
		vals := target.HomepageHeaders[h]
		if len(vals) == 0 {
			vals = target.HomepageHeaders[strings.ToLower(h)]
		}
		for _, v := range vals {
			if v != "" {
				entries = append(entries, fmt.Sprintf("%s: %s", h, v))
			}
		}
	}

	if len(entries) > 0 {
		findings = append(findings, model.InterestingFinding{
			URL:                target.EffectiveURL,
			Type:               "headers",
			Description:        "Interesting HTTP response headers",
			InterestingEntries: entries,
			FoundBy:            "Headers (Passive)",
			Confidence:         100,
		})
	}

	return findings
}

func passiveInteresting(target *Target) []model.InterestingFinding {
	var findings []model.InterestingFinding
	body := string(target.Homepage)

	pingback := target.HomepageHeaders.Get("X-Pingback")
	if pingback != "" && strings.Contains(pingback, "xmlrpc.php") {
		findings = append(findings, model.InterestingFinding{
			URL:         pingback,
			Type:        "xmlrpc",
			Description: "XML-RPC seems to be enabled",
			FoundBy:     "Headers (Passive)",
			Confidence:  100,
			References: []model.Reference{
				{Type: "url", ID: "https://codex.wordpress.org/XML-RPC_Pingback_API"},
			},
		})
	}

	xmlrpcRe := regexp.MustCompile(`<link\s+rel=["']pingback["']\s+href=["']([^"']+xmlrpc\.php)["']`)
	if m := xmlrpcRe.FindStringSubmatch(body); len(m) > 1 {
		if pingback == "" {
			findings = append(findings, model.InterestingFinding{
				URL:         m[1],
				Type:        "xmlrpc",
				Description: "XML-RPC seems to be enabled",
				FoundBy:     "Link Tag (Passive)",
				Confidence:  30,
			})
		}
	}

	if strings.Contains(body, "/wp-json/") || strings.Contains(target.HomepageHeaders.Get("Link"), "wp-json") {
		findings = append(findings, model.InterestingFinding{
			URL:         target.EffectiveURL + "wp-json/",
			Type:        "wp_json_api",
			Description: "WordPress REST API is exposed",
			FoundBy:     "Link Header/Tag (Passive)",
			Confidence:  60,
		})
	}

	return findings
}

func aggressiveInteresting(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	var findings []model.InterestingFinding

	findings = append(findings, checkRobotsTxt(ctx, client, target)...)
	findings = append(findings, checkXMLRPC(ctx, client, target)...)
	findings = append(findings, checkReadme(ctx, client, target)...)
	findings = append(findings, checkDebugLog(ctx, client, target)...)
	findings = append(findings, checkWPCron(ctx, client, target)...)
	findings = append(findings, checkRegistration(ctx, client, target)...)
	findings = append(findings, checkFullPathDisclosure(ctx, client, target)...)
	findings = append(findings, checkUploadListing(ctx, client, target)...)
	findings = append(findings, checkMultisite(ctx, client, target)...)
	findings = append(findings, checkSearchReplaceDB(ctx, client, target)...)
	findings = append(findings, checkDuplicatorLog(ctx, client, target)...)

	return findings
}

func checkRobotsTxt(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	resp, err := client.Get(ctx, target.EffectiveURL+"robots.txt")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	body := string(resp.Body)
	if !strings.Contains(strings.ToLower(body), "disallow") {
		return nil
	}

	var entries []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if path != "" && (strings.Contains(path, "wp-") || strings.Contains(path, "admin")) {
				entries = append(entries, line)
			}
		}
	}

	return []model.InterestingFinding{{
		URL:                target.EffectiveURL + "robots.txt",
		Type:               "robots_txt",
		Description:        "WordPress robots.txt found",
		InterestingEntries: entries,
		FoundBy:            "Robots Txt (Aggressive)",
		Confidence:         100,
	}}
}

func checkXMLRPC(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	xmlrpcURL := target.XMLRPCURL()

	postBody := []byte(`<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`)
	resp, err := client.Post(ctx, xmlrpcURL, "text/xml", postBody)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	body := string(resp.Body)
	if !strings.Contains(body, "<methodResponse>") {
		return nil
	}

	finding := model.InterestingFinding{
		URL:         xmlrpcURL,
		Type:        "xmlrpc",
		Description: "XML-RPC is enabled and responds to requests",
		FoundBy:     "Direct Access (Aggressive)",
		Confidence:  100,
		References: []model.Reference{
			{Type: "url", ID: "https://codex.wordpress.org/XML-RPC_Pingback_API"},
		},
	}

	if strings.Contains(body, "system.multicall") {
		finding.InterestingEntries = append(finding.InterestingEntries, "system.multicall is available (amplification attacks possible)")
	}
	if strings.Contains(body, "pingback.ping") {
		finding.InterestingEntries = append(finding.InterestingEntries, "pingback.ping is available (SSRF/DDoS possible)")
	}
	if strings.Contains(body, "wp.getUsersBlogs") {
		finding.InterestingEntries = append(finding.InterestingEntries, "wp.getUsersBlogs is available (credential testing possible)")
	}

	return []model.InterestingFinding{finding}
}

func checkReadme(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	readmePaths := []string{"readme.html", "liesmich.html", "olvasdel.html"}

	for _, p := range readmePaths {
		resp, err := client.Get(ctx, target.EffectiveURL+p)
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		if strings.Contains(strings.ToLower(string(resp.Body)), "wordpress") {
			return []model.InterestingFinding{{
				URL:         target.EffectiveURL + p,
				Type:        "readme",
				Description: "WordPress readme file found",
				FoundBy:     "Direct Access (Aggressive)",
				Confidence:  100,
			}}
		}
	}
	return nil
}

func checkDebugLog(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	url := target.EffectiveURL + target.ContentDir + "/debug.log"
	resp, err := client.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	body := string(resp.Body)
	if !strings.Contains(body, "PHP") && !strings.Contains(body, "WordPress") && !strings.Contains(body, "Fatal error") && !strings.Contains(body, "Warning") {
		return nil
	}

	return []model.InterestingFinding{{
		URL:         url,
		Type:        "debug_log",
		Description: "Debug log file found (may contain sensitive data)",
		FoundBy:     "Direct Access (Aggressive)",
		Confidence:  100,
	}}
}

func checkWPCron(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	url := target.EffectiveURL + "wp-cron.php"
	resp, err := client.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	return []model.InterestingFinding{{
		URL:         url,
		Type:        "wp_cron",
		Description: "WP-Cron is accessible (can be used for DoS or timing attacks)",
		FoundBy:     "Direct Access (Aggressive)",
		Confidence:  60,
	}}
}

func checkRegistration(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	url := target.LoginURL("") + "?action=register"
	resp, err := client.Get(ctx, url)
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 && strings.Contains(string(resp.Body), "registration-form") {
		return []model.InterestingFinding{{
			URL:         url,
			Type:        "registration",
			Description: "User registration is enabled",
			FoundBy:     "Direct Access (Aggressive)",
			Confidence:  100,
		}}
	}

	url = target.EffectiveURL + "wp-signup.php"
	resp, err = client.Get(ctx, url)
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 && strings.Contains(string(resp.Body), "signup") {
		return []model.InterestingFinding{{
			URL:         url,
			Type:        "registration",
			Description: "User registration is enabled (multisite signup)",
			FoundBy:     "Direct Access (Aggressive)",
			Confidence:  100,
		}}
	}

	return nil
}

func checkFullPathDisclosure(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	paths := []string{
		target.ContentDir + "/plugins/hello.php",
		"wp-includes/rss-functions.php",
	}

	for _, p := range paths {
		resp, err := client.Get(ctx, target.EffectiveURL+p)
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		body := string(resp.Body)
		fpRe := regexp.MustCompile(`(?i)(?:fatal error|warning|parse error|notice).*\bin\s+(/[^\s<]+\.php)`)
		if m := fpRe.FindStringSubmatch(body); len(m) > 1 {
			return []model.InterestingFinding{{
				URL:                target.EffectiveURL + p,
				Type:               "full_path_disclosure",
				Description:        "Full path disclosed via PHP error",
				InterestingEntries: []string{m[1]},
				FoundBy:            "Direct Access (Aggressive)",
				Confidence:         100,
			}}
		}
	}

	return nil
}

func checkUploadListing(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	url := target.EffectiveURL + target.ContentDir + "/uploads/"
	resp, err := client.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	if isDirectoryListing(string(resp.Body)) {
		return []model.InterestingFinding{{
			URL:         url,
			Type:        "upload_directory_listing",
			Description: "Upload directory has listing enabled",
			FoundBy:     "Direct Access (Aggressive)",
			Confidence:  100,
		}}
	}
	return nil
}

func checkMultisite(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	body := string(target.Homepage)
	if strings.Contains(body, "wp-signup.php") || strings.Contains(body, "wp-activate.php") {
		return []model.InterestingFinding{{
			URL:         target.EffectiveURL,
			Type:        "multisite",
			Description: "WordPress Multisite installation detected",
			FoundBy:     "Homepage Source (Passive)",
			Confidence:  60,
		}}
	}
	return nil
}

func checkSearchReplaceDB(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	url := target.EffectiveURL + "searchreplacedb2.php"
	resp, err := client.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	if strings.Contains(string(resp.Body), "Search") && strings.Contains(string(resp.Body), "Replace") {
		return []model.InterestingFinding{{
			URL:         url,
			Type:        "search_replace_db",
			Description: "Search Replace DB script found (CRITICAL: allows arbitrary database modifications)",
			FoundBy:     "Direct Access (Aggressive)",
			Confidence:  100,
		}}
	}
	return nil
}

func checkDuplicatorLog(ctx context.Context, client *httpclient.Client, target *Target) []model.InterestingFinding {
	paths := []string{
		"installer-log.txt",
		"dup-installer/main.installer.log",
	}

	for _, p := range paths {
		resp, err := client.Get(ctx, target.EffectiveURL+p)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if strings.Contains(strings.ToLower(string(resp.Body)), "duplicator") {
			return []model.InterestingFinding{{
				URL:         target.EffectiveURL + p,
				Type:        "duplicator_installer_log",
				Description: "Duplicator installer log found (may contain credentials)",
				FoundBy:     "Direct Access (Aggressive)",
				Confidence:  100,
			}}
		}
	}
	return nil
}

func isDirectoryListing(body string) bool {
	indicators := []string{
		"<title>Index of",
		"[To Parent Directory]",
		"<h1>Index of",
		"Directory listing for",
	}
	lower := strings.ToLower(body)
	for _, ind := range indicators {
		if strings.Contains(lower, strings.ToLower(ind)) {
			return true
		}
	}
	return false
}
