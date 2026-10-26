package scraper

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/c3xdev/c3x-pricing-api/internal/config"
	"github.com/c3xdev/c3x-pricing-api/internal/db"
)

// Live Cloud Billing body for a revoked or unknown key, captured from
// cloudbilling.googleapis.com. The reason is API_KEY_INVALID and the HTTP
// status is 400, which is also what an expired page token uses, so the
// body has to be what distinguishes them.
const gcpInvalidKeyBody = `{
  "error": {
    "code": 400,
    "message": "API key not valid. Please pass a valid API key.",
    "status": "INVALID_ARGUMENT",
    "details": [{
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "API_KEY_INVALID",
      "domain": "googleapis.com",
      "metadata": {"service": "cloudbilling.googleapis.com"}
    }]
  }
}`

func TestGCPAuthErrorClassifiesCredentialRejections(t *testing.T) {
	t.Parallel()
	planted := "AIza" + strings.Repeat("k", 35)
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
		wantHas string
	}{
		{"invalid key", http.StatusBadRequest, gcpInvalidKeyBody, true, "HTTP 400 API_KEY_INVALID"},
		{"key planted in the body stays out of the error", http.StatusBadRequest,
			strings.Replace(gcpInvalidKeyBody, "cloudbilling.googleapis.com", planted, 1),
			true, "API_KEY_INVALID"},
		{"api disabled", http.StatusForbidden,
			`{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`,
			true, "HTTP 403 SERVICE_DISABLED"},
		{"no key at all", http.StatusForbidden,
			`{"error":{"code":403,"message":"Method doesn't allow unregistered callers","status":"PERMISSION_DENIED"}}`,
			true, "HTTP 403 PERMISSION_DENIED"},
		{"unauthorized", http.StatusUnauthorized, "", true, "HTTP 401"},
		{"expired page token is not a credential failure", http.StatusBadRequest,
			`{"error":{"code":400,"message":"Invalid page token","status":"INVALID_ARGUMENT"}}`,
			false, ""},
		{"rate limit", http.StatusTooManyRequests, `{"error":{"status":"RESOURCE_EXHAUSTED"}}`, false, ""},
		{"server error mentioning the key reason", http.StatusInternalServerError,
			`{"error":{"status":"INTERNAL","details":[{"reason":"API_KEY_INVALID"}]}}`, false, ""},
		{"not found", http.StatusNotFound, `{"error":{"status":"NOT_FOUND"}}`, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := gcpAuthError(tc.status, tc.body)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("gcpAuthError(%d) = %v, want nil", tc.status, err)
				}
				return
			}
			if !errors.Is(err, errGCPAPIKeyRejected) {
				t.Fatalf("gcpAuthError(%d) = %v, want the credential sentinel", tc.status, err)
			}
			if !strings.Contains(err.Error(), "GCP API key rejected: check GCP_API_KEY / Cloud Billing API enabled") {
				t.Fatalf("error %q does not name the credential", err)
			}
			if tc.wantHas != "" && !strings.Contains(err.Error(), tc.wantHas) {
				t.Fatalf("error %q does not contain %q", err, tc.wantHas)
			}
			if strings.Contains(err.Error(), planted) || strings.Contains(err.Error(), "AIza") {
				t.Fatalf("error leaked key material: %s", err)
			}
		})
	}
}

func TestGCPScrapeAuthRejectionFailsTheRun(t *testing.T) {
	t.Parallel()
	const apiKey = "AIzaSyREJECTEDKEYREJECTEDKEYREJECTEDKEY" //nolint:gosec // G101: fake key, asserted absent from the error
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if got := r.Header.Get("X-Goog-Api-Key"); got != apiKey {
			t.Errorf("X-Goog-Api-Key = %q", got)
		}
		if r.URL.Query().Get("key") != "" {
			t.Errorf("key leaked into the URL: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, gcpInvalidKeyBody)
	}))
	t.Cleanup(srv.Close)

	s := NewGCPScraper(&config.Config{GCPAPIKey: apiKey, ScrapeConcurrency: 4})
	s.baseURL = srv.URL
	var upserted atomic.Bool
	err := s.ScrapeWithHandler(context.Background(), func(context.Context, []db.Product) error {
		upserted.Store(true)
		return nil
	})
	if !errors.Is(err, errGCPAPIKeyRejected) {
		t.Fatalf("ScrapeWithHandler err = %v, want credential rejection", err)
	}
	if strings.Contains(err.Error(), apiKey) {
		t.Fatalf("stored error contains the API key: %s", err)
	}
	if upserted.Load() {
		t.Fatal("products were upserted after a credential rejection")
	}
	// Discovery fails closed. The per-service fan-out must not run, or a
	// revoked key would again be N swallowed warnings.
	if hits.Load() != 1 {
		t.Fatalf("billing API calls = %d, want 1 (discovery only)", hits.Load())
	}
	if s.FailedServices() != 0 {
		t.Fatalf("FailedServices = %d, want 0 (the run failed, it did not swallow)", s.FailedServices())
	}
}

func TestGCPScrapeSKUAuthRejectionFailsTheRun(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/skus") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"services":[]}`)
	}))
	t.Cleanup(srv.Close)

	s := NewGCPScraper(&config.Config{GCPAPIKey: "present-but-not-a-real-key", ScrapeConcurrency: 4})
	s.baseURL = srv.URL
	err := s.ScrapeWithHandler(context.Background(), func(context.Context, []db.Product) error {
		return nil
	})
	if !errors.Is(err, errGCPAPIKeyRejected) {
		t.Fatalf("ScrapeWithHandler err = %v, want credential rejection from the SKU call", err)
	}
	if !strings.Contains(err.Error(), "SERVICE_DISABLED") {
		t.Fatalf("error %q does not name SERVICE_DISABLED", err)
	}
}

func TestGCPScrapeNonAuthHTTPErrorStaysPerService(t *testing.T) {
	t.Parallel()
	var skuCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/skus") {
			skuCalls.Add(1)
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"code":400,"message":"Invalid page token","status":"INVALID_ARGUMENT"}}`)
	}))
	t.Cleanup(srv.Close)

	s := NewGCPScraper(&config.Config{GCPAPIKey: "present-but-not-a-real-key", ScrapeConcurrency: 4})
	s.baseURL = srv.URL
	err := s.ScrapeWithHandler(context.Background(), func(context.Context, []db.Product) error {
		t.Fatal("handler called")
		return nil
	})
	if err != nil {
		t.Fatalf("per-service HTTP 400 aborted the scrape: %v", err)
	}
	if int(skuCalls.Load()) != len(gcpServices) {
		t.Fatalf("sku calls = %d, want %d hard-coded services", skuCalls.Load(), len(gcpServices))
	}
	if s.FailedServices() != int64(len(gcpServices)) {
		t.Fatalf("FailedServices = %d, want %d", s.FailedServices(), len(gcpServices))
	}
}
