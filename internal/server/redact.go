package server

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/c3xdev/c3x-pricing-api/internal/config"
)

// Patterns that show up when a scrape error wraps a request URL, an env
// assignment, or a cloud error that echoed the caller's credential.
// Applied when /status reads scrape_runs.error, so a row written before
// this redaction existed cannot leak through the public endpoint.
var (
	// 20+ so a key truncated by the 2000-char scrape_runs limit still matches.
	gcpAPIKeyRE    = regexp.MustCompile(`AIza[0-9A-Za-z_-]{20,}`)
	awsAccessKeyRE = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	// Query credentials only. A bare "key=" would also hit unrelated text;
	// pageToken= must survive so a pagination error stays readable.
	sensitiveQueryRE = regexp.MustCompile(`(?i)([?&](?:api[_-]?key|apikey|x-goog-api-key|access[_-]?token|client[_-]?secret|aws_secret_access_key|signature|secret|password|token|key)=)[^&#\s"']+`)
	envAssignRE      = regexp.MustCompile(`(?i)\b(GCP_API_KEY|API_KEY|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL|SECRET_KEY|PASSWORD)\b(\s*[=:]\s*)\S+`)
	// Authorization consumes an optional Bearer scheme so the token is one
	// replacement, not "Bearer" left behind as a second word.
	authHeaderRE  = regexp.MustCompile(`(?i)\b(Authorization)(\s*[:=]\s*)(?:Bearer\s+)?\S+`)
	bearerRE      = regexp.MustCompile(`(?i)\bBearer\s+\S+`)
	headerKeyRE   = regexp.MustCompile(`(?i)\b(X-Goog-Api-Key)(\s*[:=]\s*)\S+`)
	urlUserinfoRE = regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^/\s:@]+):[^@\s/]+@`)
)

const scrapeErrorMaxLen = 1000

// redactSecrets removes credential material from a scrape error. It is
// defensive: the scrapers already keep the GCP key out of request URLs,
// and this still has to catch a row that was stored the old way.
func redactSecrets(s string) string {
	if s == "" {
		return ""
	}
	s = urlUserinfoRE.ReplaceAllString(s, "${1}:[REDACTED]@")
	s = authHeaderRE.ReplaceAllString(s, "${1}${2}[REDACTED]")
	s = bearerRE.ReplaceAllString(s, "Bearer [REDACTED]")
	s = headerKeyRE.ReplaceAllString(s, "${1}${2}[REDACTED]")
	s = envAssignRE.ReplaceAllString(s, "${1}${2}[REDACTED]")
	s = sensitiveQueryRE.ReplaceAllString(s, "${1}[REDACTED]")
	s = gcpAPIKeyRE.ReplaceAllString(s, "[REDACTED]")
	s = awsAccessKeyRE.ReplaceAllString(s, "[REDACTED]")
	return s
}

// redactLiteral removes an exact secret, such as the configured API key
// when it does not match a known vendor pattern. Secrets shorter than 8
// characters are ignored so a short placeholder cannot punch holes in
// unrelated error text.
func redactLiteral(s, literal string) string {
	if s == "" || len(literal) < 8 {
		return s
	}
	return strings.ReplaceAll(s, literal, "[REDACTED]")
}

// exposeScrapeError is the form /status publishes. One line, capped, and
// redacted. Empty means the field should be omitted.
func exposeScrapeError(raw string) string {
	s := strings.TrimSpace(redactSecrets(raw))
	if s == "" {
		return ""
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= scrapeErrorMaxLen {
		return s
	}
	i := scrapeErrorMaxLen
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + "..."
}

// redactConfiguredSecrets removes credentials this process was actually
// given, on top of the pattern redaction in exposeScrapeError.
func redactConfiguredSecrets(cfg *config.Config, raw string) string {
	if cfg == nil || raw == "" {
		return raw
	}
	raw = redactLiteral(raw, cfg.GCPAPIKey)
	raw = redactLiteral(raw, cfg.APIKey)
	raw = redactLiteral(raw, cfg.DatabaseURL)
	if u, err := url.Parse(cfg.DatabaseURL); err == nil && u.User != nil {
		if p, ok := u.User.Password(); ok {
			raw = redactLiteral(raw, p)
		}
	}
	return raw
}
