package server

import (
	"strings"
	"testing"

	"github.com/c3xdev/c3x-pricing-api/internal/config"
)

func TestRedactSecretsKeepsCredentialMaterialOut(t *testing.T) {
	t.Parallel()
	gcpKey := "AIza" + strings.Repeat("k", 35)
	awsKey := "AKIAIOSFODNN7EXAMPLE"              //nolint:gosec // G101: AWS docs example id, must be redacted
	token := "ya29.a0AfH6SMDummyTokenValue123456" //nolint:gosec // G101: fake bearer token, must be redacted
	cases := []struct {
		name      string
		in        string
		forbidden []string
		wantHas   []string
	}{
		{
			name:      "google api key",
			in:        "fetch failed: " + gcpKey,
			forbidden: []string{gcpKey, "AIza"},
		},
		{
			name:      "key in query string, page token survives",
			in:        "https://cloudbilling.googleapis.com/v1/services?pageSize=500&key=" + gcpKey + "&pageToken=abc",
			forbidden: []string{gcpKey},
			wantHas:   []string{"pageToken=abc", "pageSize=500", "key=[REDACTED]"},
		},
		{
			name:      "header",
			in:        "request used X-Goog-Api-Key: " + gcpKey,
			forbidden: []string{gcpKey},
			wantHas:   []string{"X-Goog-Api-Key: [REDACTED]"},
		},
		{
			name:      "bearer",
			in:        "Authorization: Bearer " + token,
			forbidden: []string{token},
			wantHas:   []string{"Authorization: [REDACTED]"},
		},
		{
			name:      "aws access key id",
			in:        "upstream said " + awsKey,
			forbidden: []string{awsKey},
		},
		{
			name:      "database url userinfo",
			in:        "connect postgres://pricing:supersecret@db.internal:5432/c3x?sslmode=require",
			forbidden: []string{"supersecret"},
			wantHas:   []string{"postgres://pricing:[REDACTED]@db.internal:5432/c3x"},
		},
		{
			name:      "env assignment",
			in:        "GCP_API_KEY=" + gcpKey + " was rejected",
			forbidden: []string{gcpKey},
			wantHas:   []string{"GCP_API_KEY=[REDACTED]"},
		},
		{
			name: "credential message is left readable",
			in:   "GCP API key rejected: check GCP_API_KEY / Cloud Billing API enabled (HTTP 400 API_KEY_INVALID)",
			wantHas: []string{
				"GCP API key rejected: check GCP_API_KEY / Cloud Billing API enabled (HTTP 400 API_KEY_INVALID)",
			},
		},
		{
			name:    "generic empty-scrape error is unchanged",
			in:      "scrape ingested 0 products and 21 service(s) failed: check the vendor credentials and upstream API",
			wantHas: []string{"scrape ingested 0 products and 21 service(s) failed: check the vendor credentials and upstream API"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := exposeScrapeError(tc.in)
			for _, secret := range tc.forbidden {
				if strings.Contains(got, secret) {
					t.Errorf("exposeScrapeError leaked %q in %q", secret, got)
				}
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(got, want) {
					t.Errorf("exposeScrapeError(%q) = %q, want it to contain %q", tc.in, got, want)
				}
			}
		})
	}
}

func TestExposeScrapeErrorCollapsesWhitespaceAndCapsLength(t *testing.T) {
	t.Parallel()
	got := exposeScrapeError("line one\n\nline\ttwo")
	if got != "line one line two" {
		t.Fatalf("got %q", got)
	}
	if exposeScrapeError("   ") != "" {
		t.Fatal("blank error should be omitted")
	}
	long := strings.Repeat("x", scrapeErrorMaxLen+50)
	got = exposeScrapeError(long)
	if len(got) != scrapeErrorMaxLen+3 { // "..."
		t.Fatalf("len = %d, want %d", len(got), scrapeErrorMaxLen+3)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("got %q", got[len(got)-10:])
	}
}

func TestRedactConfiguredSecretsRemovesNonPatternKey(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:gosec // G101: fixture values so redaction is tested against a URL password
		GCPAPIKey:   "custom-billing-key-99",                                              //nolint:gosec // G101: fake key, must be redacted
		APIKey:      "short",                                                              // under the 8-char floor; must not be stripped from prose
		DatabaseURL: "postgres://pricing:db-password@db:5432/c3x_pricing?sslmode=disable", //nolint:gosec // G101: fixture URL, password must be redacted
	}
	in := "custom-billing-key-99 failed; short note; db-password; " + cfg.DatabaseURL
	got := exposeScrapeError(redactConfiguredSecrets(cfg, in))
	for _, secret := range []string{"custom-billing-key-99", "db-password", cfg.DatabaseURL} {
		if strings.Contains(got, secret) {
			t.Errorf("leaked %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "short note") {
		t.Fatalf("short configured value was stripped from prose: %q", got)
	}
}

func TestRedactLiteralIgnoresShortValues(t *testing.T) {
	t.Parallel()
	if got := redactLiteral("api key missing", "key"); got != "api key missing" {
		t.Fatalf("got %q", got)
	}
}
