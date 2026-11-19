package myrasec

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const sslCertificateSavedWithWarnings = `{"error": false, "data": [
	{"id": 7, "created": "2026-11-18T10:00:00Z", "modified": "2026-11-18T10:00:00Z", "subject": "CN=example.com", "subjectAlternatives": ["example.com"], "subdomains": ["example.com"]}
], "warningList": [
	{"propertyPath": "intermediates", "message": "The chain has no intermediate certificate.", "code": "CHAIN_INTERMEDIATE_MISSING"},
	{"propertyPath": "cert", "message": "The certificate expires in 10 days.", "code": "LEAF_EXPIRES_SOON", "parameters": {"days": 10}}
]}`

const sslCertificateStored = `{"error": false, "data": [
	{"id": 7, "created": "2026-11-18T10:00:00Z", "modified": "2026-11-18T10:00:00Z", "subject": "CN=example.com", "subjectAlternatives": ["example.com"], "subdomains": ["example.com"]}
]}`

const sslCertificateRejected = `{"error": true, "data": [], "violationList": [
	{"propertyPath": "cert", "message": "The certificate has expired.", "code": "LEAF_EXPIRED"},
	{"propertyPath": "intermediates[0].cert", "message": "Intermediate certificate 1 was not issued with the expected key.", "code": "INTERMEDIATE_WRONG_KEY"}
]}`

func newSSLCertificateResourceData(t *testing.T) *schema.ResourceData {
	t.Helper()
	d := resourceMyrasecSSLCertificate().TestResourceData()
	values := map[string]any{"domain_name": "example.com", "domain_id": 1, "certificate": "-----BEGIN CERTIFICATE-----", "key": "key"}
	for k, v := range values {
		if err := d.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func sslCertificateSaveHandler(t *testing.T, method, path string, status int, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == method && r.URL.Path == path:
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		case r.Method == http.MethodGet && r.URL.Path == "/domain/1/ALL-1/settings":
			_, _ = w.Write([]byte(`{"error": false, "domain": [], "parent": [], "list": [{}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/domain/1/ssl/certificates/7":
			_, _ = w.Write([]byte(sslCertificateStored))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}
}

func warningDetails(diags diag.Diagnostics) []string {
	var details []string
	for _, d := range diags {
		if d.Severity == diag.Warning {
			details = append(details, d.Detail)
		}
	}
	return details
}

func assertSSLCertificateWarnings(t *testing.T, diags diag.Diagnostics) {
	t.Helper()
	if diags.HasError() {
		t.Fatalf("a warning-only save failed the apply: %v", diags)
	}
	want := []string{
		"intermediates: The chain has no intermediate certificate. [CHAIN_INTERMEDIATE_MISSING]",
		"cert: The certificate expires in 10 days. [LEAF_EXPIRES_SOON]",
	}
	got := warningDetails(diags)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("warning diagnostics = %q, want %q", got, want)
	}
}

func TestSSLCertificateCreateReportsAPIWarnings(t *testing.T) {
	client := domainTestClient(t, sslCertificateSaveHandler(t, http.MethodPost, "/domain/1/certificates", http.StatusOK, sslCertificateSavedWithWarnings))
	d := newSSLCertificateResourceData(t)

	diags := resourceMyrasecSSLCertificateCreate(context.Background(), d, client)

	assertSSLCertificateWarnings(t, diags)
	if d.Id() != "7" {
		t.Errorf("id = %q, want 7", d.Id())
	}
}

func storedSSLCertificateResourceData(t *testing.T, diff *terraform.InstanceDiff) *schema.ResourceData {
	t.Helper()
	d, err := schema.InternalMap(resourceMyrasecSSLCertificate().Schema).Data(&terraform.InstanceState{ID: "7", Attributes: map[string]string{
		"domain_name": "example.com", "domain_id": "1", "certificate_id": "7",
		"certificate": "-----BEGIN CERTIFICATE-----", "key": "key",
	}}, diff)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSSLCertificateUpdateReportsAPIWarnings(t *testing.T) {
	client := domainTestClient(t, sslCertificateSaveHandler(t, http.MethodPut, "/domain/1/certificates/7", http.StatusOK, sslCertificateSavedWithWarnings))
	d := storedSSLCertificateResourceData(t, nil)

	diags := resourceMyrasecSSLCertificateUpdate(context.Background(), d, client)

	assertSSLCertificateWarnings(t, diags)
}

func TestSSLCertificateReplaceReportsAPIWarnings(t *testing.T) {
	client := domainTestClient(t, sslCertificateSaveHandler(t, http.MethodPost, "/domain/1/certificates", http.StatusOK, sslCertificateSavedWithWarnings))
	d := storedSSLCertificateResourceData(t, &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
		"certificate": {Old: "-----BEGIN CERTIFICATE-----", New: "-----BEGIN CERTIFICATE----- renewed"},
	}})

	diags := resourceMyrasecSSLCertificateUpdate(context.Background(), d, client)

	assertSSLCertificateWarnings(t, diags)
}

func TestSSLCertificateCreateRejectedKeepsNoState(t *testing.T) {
	client := domainTestClient(t, sslCertificateSaveHandler(t, http.MethodPost, "/domain/1/certificates", http.StatusBadRequest, sslCertificateRejected))
	d := newSSLCertificateResourceData(t)

	diags := resourceMyrasecSSLCertificateCreate(context.Background(), d, client)

	if !diags.HasError() {
		t.Fatalf("a rejected upload did not fail the apply: %v", diags)
	}
	for _, want := range []string{
		"cert: The certificate has expired. [LEAF_EXPIRED]",
		"intermediates[0].cert: Intermediate certificate 1 was not issued with the expected key. [INTERMEDIATE_WRONG_KEY]",
	} {
		if !strings.Contains(diags[0].Detail, want) {
			t.Errorf("error detail %q is missing %q", diags[0].Detail, want)
		}
	}
	if len(warningDetails(diags)) != 0 {
		t.Errorf("a rejected upload reported warnings: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("a rejected upload set the id %q", d.Id())
	}
}
