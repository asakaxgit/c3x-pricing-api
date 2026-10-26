package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestVendorStatus pins the states /status reports. The motivating case is
// the third one: a vendor whose credential is revoked scrapes nothing, and
// under the previous logic kept reporting "ready" forever because readiness
// was read off the newest successful run and nothing ever downgraded it.
func TestVendorStatus(t *testing.T) {
	t.Parallel()
	now := time.Now()
	recent := now.Add(-2 * time.Hour)
	old := now.Add(-72 * time.Hour)

	cases := []struct {
		name            string
		sawSuccess      bool
		successProducts int64
		latestStatus    string
		finishedAt      *time.Time
		want            string
	}{
		{"no runs at all", false, 0, "", nil, "never"},
		{"run in flight", false, 0, "running", nil, "scraping"},
		{"healthy", true, 2_400_000, "success", &recent, "ready"},

		// The GCP case: a run recorded success while ingesting nothing.
		{"last success ingested nothing", true, 0, "success", &recent, "empty"},

		// Once the scraper started failing honestly, the failure must win
		// over the older successful run that still has a product count.
		{"latest run failed, older success exists", true, 2_400_000, "failed", &recent, "failed"},

		// A failure outranks staleness: it is the more actionable fact.
		{"failed and old", true, 2_400_000, "failed", &old, "failed"},

		{"nothing finished in 48h", true, 2_400_000, "success", &old, "stale"},

		// Running outranks everything: the picture is mid-change.
		{"scraping over a previous failure", true, 10, "running", &recent, "scraping"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := vendorStatus(tc.sawSuccess, tc.successProducts, tc.latestStatus, tc.finishedAt)
			if got != tc.want {
				t.Errorf("vendorStatus(sawSuccess=%v, products=%d, latest=%q) = %q, want %q",
					tc.sawSuccess, tc.successProducts, tc.latestStatus, got, tc.want)
			}
		})
	}
}

// TestVendorStatusNeverReportsReadyWithoutData is the invariant that matters:
// no combination of inputs may report "ready" while the last successful
// scrape ingested nothing.
func TestVendorLastErrorIsAdditiveAndRedacted(t *testing.T) {
	t.Parallel()
	gcpKey := "AIza" + strings.Repeat("k", 35)
	vendors := map[string]*vendorInfo{
		"aws":   {Status: "ready", Products: 10},
		"azure": {Status: "ready", Products: 10},
		"gcp":   {Status: "failed", Products: 0},
	}
	setVendorLastError(vendors, "gcp", "rejected key "+gcpKey+"\nsecond line")
	setVendorLastError(vendors, "azure", "   ")
	setVendorLastError(vendors, "other", "should not appear")

	if vendors["azure"].LastError != "" {
		t.Fatalf("blank error was published: %q", vendors["azure"].LastError)
	}
	if strings.Contains(vendors["gcp"].LastError, gcpKey) || strings.Contains(vendors["gcp"].LastError, "\n") {
		t.Fatalf("lastError = %q", vendors["gcp"].LastError)
	}
	if vendors["gcp"].LastError != "rejected key [REDACTED] second line" {
		t.Fatalf("lastError = %q", vendors["gcp"].LastError)
	}

	body, err := json.Marshal(vendors["gcp"])
	if err != nil {
		t.Fatal(err)
	}
	var gcp struct {
		Status    string `json:"status"`
		Products  int64  `json:"products"`
		LastError string `json:"lastError"`
	}
	if err := json.Unmarshal(body, &gcp); err != nil {
		t.Fatal(err)
	}
	if gcp.Status != "failed" || gcp.Products != 0 || gcp.LastError == "" {
		t.Fatalf("gcp payload = %+v", gcp)
	}
	if strings.Contains(string(body), gcpKey) {
		t.Fatalf("JSON leaked the key: %s", body)
	}
	// Vendors with no failed run omit the field. An empty string would
	// still be a shape change for clients that treat presence as failure.
	for _, name := range []string{"aws", "azure"} {
		frag, err := json.Marshal(vendors[name])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(frag), "lastError") {
			t.Fatalf("%s JSON includes lastError: %s", name, frag)
		}
	}
}

func TestVendorStatusNeverReportsReadyWithoutData(t *testing.T) {
	t.Parallel()
	now := time.Now()
	for _, latest := range []string{"", "success", "failed", "running"} {
		for _, fin := range []*time.Time{nil, &now} {
			if got := vendorStatus(true, 0, latest, fin); got == "ready" {
				t.Errorf("reported ready with 0 products (latest=%q, finishedAt=%v)", latest, fin)
			}
		}
	}
}
