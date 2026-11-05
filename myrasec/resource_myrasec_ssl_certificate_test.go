package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func sslCertificateResourceData(t *testing.T) *schema.ResourceData {
	t.Helper()
	d := resourceMyrasecSSLCertificate().TestResourceData()
	d.SetId("1")
	for k, v := range map[string]any{"domain_name": "example.com", "domain_id": 1, "certificate_id": 1} {
		if err := d.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// TestSSLCertificateReadErrorPreservesState pins the read behaviour on API errors: a
// certificate that no longer exists is dropped from the state, every other error keeps the
// state and fails the run instead of planning a recreation.
func TestSSLCertificateReadErrorPreservesState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		message string
		removed bool
	}{
		{name: "deleted", status: http.StatusForbidden, message: "The entity does not exist.", removed: true},
		{name: "HTTP not found", status: http.StatusNotFound, message: "not found", removed: true},
		{name: "forbidden with a message", status: http.StatusForbidden, message: "read denied"},
		{name: "forbidden without body", status: http.StatusForbidden},
		{name: "server error", status: http.StatusInternalServerError, message: "server error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/domain/1/ssl/certificates/1" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				if tc.message == "" {
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"error": true, "violationList": []any{map[string]string{"message": tc.message}}})
			}))
			d := sslCertificateResourceData(t)
			diags := resourceMyrasecSSLCertificateRead(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("missing certificate was not dropped: id=%q diags=%v", d.Id(), diags)
				}
				return
			}
			want := tc.message
			if want == "" {
				want = http.StatusText(tc.status)
			}
			if !diags.HasError() || !strings.Contains(diags[0].Detail, want) {
				t.Fatalf("API error was lost: %v", diags)
			}
			if d.Id() != "1" || d.Get("certificate_id") != 1 {
				t.Errorf("state was cleared after the API error: id=%q certificate_id=%v", d.Id(), d.Get("certificate_id"))
			}
		})
	}
}

func TestSSLCertificateConfigurationNameValidation(t *testing.T) {
	r := resourceMyrasecSSLCertificate()

	validate := r.Schema["configuration_name"].ValidateFunc
	if validate == nil {
		t.Fatal("configuration_name is expected to have a ValidateFunc")
	}

	tests := []struct {
		name      string
		value     string
		wantValid bool
	}{
		{name: "myra global default", value: "Myra-Global-TLS-Default", wantValid: true},
		{name: "2023 intermediate", value: "2023-mozilla-intermediate", wantValid: true},
		{name: "2023 modern", value: "2023-mozilla-modern", wantValid: true},
		{name: "2026 intermediate", value: "2026-mozilla-intermediate", wantValid: true},
		{name: "unknown profile", value: "not-a-profile", wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := validate(tt.value, "configuration_name")
			if tt.wantValid && len(errs) > 0 {
				t.Errorf("configuration_name %q should be valid: %v", tt.value, errs)
			}
			if !tt.wantValid && len(errs) == 0 {
				t.Errorf("configuration_name %q should be invalid", tt.value)
			}
		})
	}
}

// TestSetSSLCertificateDataValidity covers a certificate without validity dates: the API
// returns null for them on some certificates and the read must not panic.
func TestSetSSLCertificateDataValidity(t *testing.T) {
	now, err := types.ParseDate("2026-10-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	validTo, err := types.ParseDate("2027-01-01T00:00:00+01:00")
	if err != nil {
		t.Fatal(err)
	}

	d := resourceMyrasecSSLCertificate().TestResourceData()
	setSSLCertificateData(d, &myrasec.SSLCertificate{Certificate: &myrasec.Certificate{ID: 1, Created: now, Modified: now}}, "example.com", 1)
	if d.Get("valid_from") != "" || d.Get("valid_to") != "" {
		t.Errorf("valid_from=%q valid_to=%q, want empty", d.Get("valid_from"), d.Get("valid_to"))
	}

	setSSLCertificateData(d, &myrasec.SSLCertificate{Certificate: &myrasec.Certificate{ID: 1, Created: now, Modified: now, ValidFrom: now, ValidTo: validTo}}, "example.com", 1)
	if d.Get("valid_from") != "2026-10-01T00:00:00Z" || d.Get("valid_to") != "2027-01-01T00:00:00+01:00" {
		t.Errorf("valid_from=%q valid_to=%q", d.Get("valid_from"), d.Get("valid_to"))
	}
}
