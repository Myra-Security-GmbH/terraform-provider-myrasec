package myrasec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cty/cty"
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
		"intermediate: The chain has no intermediate certificate. [CHAIN_INTERMEDIATE_MISSING]",
		"certificate: The certificate expires in 10 days. [LEAF_EXPIRES_SOON]",
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
	if got := d.State().Attributes["certificate"]; got != "-----BEGIN CERTIFICATE----- renewed" {
		t.Errorf("state certificate = %q after a successful replace, want the renewed one", got)
	}
}

func TestSSLCertificateRejectedUpdateKeepsTheStoredMaterialInState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
		diff   *terraform.InstanceDiff
	}{
		{name: "update", method: http.MethodPut, path: "/domain/1/certificates/7", diff: &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
			"subdomains.#":                     {Old: "0", New: "1"},
			sslSubdomainKey("www.example.com"): {New: "www.example.com"},
		}}},
		{name: "replace", method: http.MethodPost, path: "/domain/1/certificates", diff: &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
			"certificate": {Old: "-----BEGIN CERTIFICATE-----", New: "-----BEGIN CERTIFICATE----- renewed"},
			"key":         {Old: "key", New: "renewed key"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, sslCertificateSaveHandler(t, tc.method, tc.path, http.StatusBadRequest, sslCertificateRejected))
			d := storedSSLCertificateResourceData(t, tc.diff)

			diags := resourceMyrasecSSLCertificateUpdate(context.Background(), d, client)

			if !diags.HasError() {
				t.Fatalf("a rejected %s did not fail the apply: %v", tc.name, diags)
			}
			state := d.State()
			if state.Attributes["certificate"] != "-----BEGIN CERTIFICATE-----" || state.Attributes["key"] != "key" {
				t.Errorf("a rejected %s wrote the proposed material into state: certificate=%q key=%q", tc.name, state.Attributes["certificate"], state.Attributes["key"])
			}
			if state.ID != "7" || (state.Attributes["subdomains.#"] != "" && state.Attributes["subdomains.#"] != "0") {
				t.Errorf("a rejected %s changed the stored state: id=%q subdomains=%q", tc.name, state.ID, state.Attributes["subdomains.#"])
			}
			for key, value := range state.Attributes {
				if strings.HasPrefix(key, "subdomains.") && value == "www.example.com" {
					t.Errorf("a rejected %s wrote the proposed subdomain into state: %s=%q", tc.name, key, value)
				}
			}
		})
	}
}

func TestSSLCertificateCreateRejectedKeepsNoState(t *testing.T) {
	client := domainTestClient(t, sslCertificateSaveHandler(t, http.MethodPost, "/domain/1/certificates", http.StatusBadRequest, sslCertificateRejected))
	d := newSSLCertificateResourceData(t)

	diags := resourceMyrasecSSLCertificateCreate(context.Background(), d, client)

	if !diags.HasError() {
		t.Fatalf("a rejected upload did not fail the apply: %v", diags)
	}
	want := []string{
		"certificate: The certificate has expired. [LEAF_EXPIRED]",
		"intermediate 1: Intermediate certificate 1 was not issued with the expected key. [INTERMEDIATE_WRONG_KEY]",
	}
	if len(diags) != len(want) {
		t.Fatalf("diagnostics = %v, want one error per violation", diags)
	}
	for i, w := range want {
		if diags[i].Severity != diag.Error || diags[i].Detail != w {
			t.Errorf("diagnostic %d = %q, want the error %q", i, diags[i].Detail, w)
		}
	}
	if !diags[0].AttributePath.Equals(cty.GetAttrPath("certificate")) || !diags[1].AttributePath.Equals(cty.GetAttrPath("intermediate")) {
		t.Errorf("attribute paths = %v and %v, want certificate and intermediate", diags[0].AttributePath, diags[1].AttributePath)
	}
	if len(warningDetails(diags)) != 0 {
		t.Errorf("a rejected upload reported warnings: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("a rejected upload set the id %q", d.Id())
	}
}

func sslSubdomainKey(name string) string {
	elem := resourceMyrasecSSLCertificate().Schema["subdomains"].Elem.(*schema.Schema)
	return "subdomains." + strconv.Itoa(schema.HashSchema(elem)(name))
}

func testIntermediatePEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Myra Test"}, CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSSLCertificateRejectedSaveNamesTheSentIntermediateAndKeepsItsWarnings(t *testing.T) {
	const rejected = `{"error": true, "data": [], "violationList": [
		{"propertyPath": "intermediates[1].cert", "message": "Intermediate certificate 2 has expired.", "code": "INTERMEDIATE_EXPIRED"}
	], "warningList": [
		{"propertyPath": "key", "message": "The key is short.", "code": "KEY_WEAK"}
	]}`
	client := domainTestClient(t, sslCertificateSaveHandler(t, http.MethodPost, "/domain/1/certificates", http.StatusBadRequest, rejected))
	d := newSSLCertificateResourceData(t)
	if err := d.Set("intermediate", []any{
		map[string]any{"certificate": testIntermediatePEM(t, "First Test Intermediate")},
		map[string]any{"certificate": testIntermediatePEM(t, "Second Test Intermediate")},
	}); err != nil {
		t.Fatal(err)
	}
	sent, err := buildSSLCertificate(d)
	if err != nil {
		t.Fatal(err)
	}
	subject := sentIntermediateSubject(1, sent.Intermediates)
	if !strings.Contains(subject, "Test Intermediate") {
		t.Fatalf("subject of the second sent intermediate = %q", subject)
	}

	diags := resourceMyrasecSSLCertificateCreate(context.Background(), d, client)

	if len(diags) != 2 {
		t.Fatalf("diagnostics = %v, want the error and the warning", diags)
	}
	wantError := "intermediate \"" + subject + "\": Intermediate certificate 2 has expired. [INTERMEDIATE_EXPIRED]"
	if diags[0].Severity != diag.Error || diags[0].Detail != wantError || !diags[0].AttributePath.Equals(cty.GetAttrPath("intermediate")) {
		t.Errorf("error = %q on %v, want %q on intermediate", diags[0].Detail, diags[0].AttributePath, wantError)
	}
	if diags[1].Severity != diag.Warning || diags[1].Detail != "key: The key is short. [KEY_WEAK]" || !diags[1].AttributePath.Equals(cty.GetAttrPath("key")) {
		t.Errorf("warning = %q on %v, want the key warning", diags[1].Detail, diags[1].AttributePath)
	}
}

func TestLocateSSLCertificateFinding(t *testing.T) {
	for _, tc := range []struct {
		path       string
		parameters map[string]any
		attribute  string
		label      string
	}{
		{path: "", attribute: "", label: ""},
		{path: "cert", attribute: "certificate", label: "certificate"},
		{path: "key", attribute: "key", label: "key"},
		{path: "intermediates", attribute: "intermediate", label: "intermediate"},
		{path: "intermediates[3].cert", parameters: map[string]any{"subject": "CN=From The API"}, attribute: "intermediate", label: `intermediate "CN=From The API"`},
		{path: "intermediates[3].cert", attribute: "intermediate", label: "intermediate 4"},
		{path: "id", attribute: "", label: "id"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got := locateSSLCertificateFinding(tc.path, tc.parameters, nil)
			if got.attribute != tc.attribute || got.label != tc.label {
				t.Errorf("locate(%q) = %+v, want attribute %q label %q", tc.path, got, tc.attribute, tc.label)
			}
		})
	}
}
