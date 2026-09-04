package myrasec

import (
	"context"
	"strconv"
	"strings"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestSSLCertificateRequestInternalValidate(t *testing.T) {
	if err := resourceMyrasecSSLCertificateRequest().InternalValidate(nil, true); err != nil {
		t.Fatalf("resource schema invalid: %v", err)
	}
	if err := dataSourceMyrasecSSLCertificateRequests().InternalValidate(nil, false); err != nil {
		t.Fatalf("data source schema invalid: %v", err)
	}
	if err := dataSourceMyrasecSSLCertificateRequestDomainChecks().InternalValidate(nil, false); err != nil {
		t.Fatalf("domain checks data source schema invalid: %v", err)
	}
}

func TestBuildSSLCertificateRequest(t *testing.T) {
	d := resourceMyrasecSSLCertificateRequest().TestResourceData()

	d.Set("certificate_provider", "SECTIGO")
	d.Set("algorithm", "RSA4096")
	d.Set("subject_alternative_names", []any{"www.example.com", "*.example.org"})
	d.Set("subdomains", []any{"www.example.com"})
	d.Set("ssl_provider_credentials_id", 42)
	d.Set("renewal_interval", 30)
	d.Set("signature_algorithm", "SHA384")

	request := buildSSLCertificateRequest(d)

	if request.ID != 0 {
		t.Errorf("ID = %d, want 0 on build", request.ID)
	}
	if request.Provider != "SECTIGO" {
		t.Errorf("Provider = %q, want SECTIGO", request.Provider)
	}
	if request.Algorithm != "RSA4096" {
		t.Errorf("Algorithm = %q, want RSA4096", request.Algorithm)
	}
	if request.SSLProviderCredentialsID != 42 {
		t.Errorf("SSLProviderCredentialsID = %d, want 42", request.SSLProviderCredentialsID)
	}
	if request.RenewalInterval != 30 {
		t.Errorf("RenewalInterval = %d, want 30", request.RenewalInterval)
	}
	if request.SignatureAlgorithm != "SHA384" {
		t.Errorf("SignatureAlgorithm = %q, want SHA384", request.SignatureAlgorithm)
	}

	names := make(map[string]bool)
	for _, san := range request.SubjectAlternativeNames {
		names[san.Name] = true
	}
	if len(names) != 2 || !names["www.example.com"] || !names["*.example.org"] {
		t.Errorf("SubjectAlternativeNames = %v, want www.example.com and *.example.org", request.SubjectAlternativeNames)
	}

	if len(request.Assignments) != 1 || request.Assignments[0].SubDomainName != "www.example.com" {
		t.Errorf("Assignments = %v, want www.example.com", request.Assignments)
	}
}

func TestBuildSSLCertificateRequestEmptyCollections(t *testing.T) {
	d := resourceMyrasecSSLCertificateRequest().TestResourceData()

	d.Set("certificate_provider", "LETS_ENCRYPT")
	d.Set("algorithm", "ECDSA256")

	request := buildSSLCertificateRequest(d)

	if request.SubjectAlternativeNames == nil {
		t.Error("SubjectAlternativeNames should be an empty slice, not nil")
	}
	if request.Assignments == nil {
		t.Error("Assignments should be an empty slice, not nil")
	}
}

func TestFindRedundantSAN(t *testing.T) {
	tests := []struct {
		name         string
		names        []string
		wantName     string
		wantWildcard string
	}{
		{
			name:  "no wildcard",
			names: []string{"www.example.com", "api.example.com"},
		},
		{
			name:  "wildcard without covered name",
			names: []string{"*.example.com", "example.com", "a.b.example.com"},
		},
		{
			name:         "covered name",
			names:        []string{"*.example.com", "www.example.com"},
			wantName:     "www.example.com",
			wantWildcard: "*.example.com",
		},
		{
			name:         "covered name with different case",
			names:        []string{"*.Example.com", "www.example.com"},
			wantName:     "www.example.com",
			wantWildcard: "*.example.com",
		},
		{
			name:  "wildcard of another domain",
			names: []string{"*.example.org", "www.example.com"},
		},
		{
			name:         "wildcard with trailing dot",
			names:        []string{"*.example.com.", "www.example.com"},
			wantName:     "www.example.com",
			wantWildcard: "*.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, wildcard := findRedundantSAN(tt.names)
			if name != tt.wantName || wildcard != tt.wantWildcard {
				t.Errorf("findRedundantSAN() = (%q, %q), want (%q, %q)", name, wildcard, tt.wantName, tt.wantWildcard)
			}
		})
	}
}

func TestSSLCertificateRequestCustomizeDiff(t *testing.T) {
	// sectigoState is the state of a Sectigo request with every provider specific attribute set
	sectigoState := &terraform.InstanceState{
		ID: "1",
		Attributes: map[string]string{
			"id":                          "1",
			"request_id":                  "1",
			"certificate_provider":        "SECTIGO",
			"algorithm":                   "RSA2048",
			"subject_alternative_names.#": "1",
			"subject_alternative_names." + strconv.Itoa(hashDomainName("www.example.com")): "www.example.com",
			"ssl_provider_credentials_id": "7",
			"renewal_interval":            "30",
			"signature_algorithm":         "SHA384",
			"status":                      "CREATED",
		},
	}

	tests := []struct {
		name    string
		state   *terraform.InstanceState
		config  map[string]any
		wantErr string
	}{
		{
			name:  "switch sectigo to lets encrypt drops provider specific attributes",
			state: sectigoState,
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
			},
		},
		{
			name:  "switch sectigo to lets encrypt keeps stale signature algorithm",
			state: sectigoState,
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
				"signature_algorithm":       "SHA384",
			},
			wantErr: "signature_algorithm is accepted",
		},
		{
			name: "valid lets encrypt",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "ECDSA256",
				"subject_alternative_names": []any{"www.example.com"},
			},
		},
		{
			name: "valid sectigo",
			config: map[string]any{
				"certificate_provider":        "SECTIGO",
				"algorithm":                   "RSA4096",
				"subject_alternative_names":   []any{"www.example.com"},
				"ssl_provider_credentials_id": 7,
				"renewal_interval":            30,
				"signature_algorithm":         "SHA384",
			},
		},
		{
			name: "lets encrypt rejects RSA4096",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA4096",
				"subject_alternative_names": []any{"www.example.com"},
			},
			wantErr: "LETS_ENCRYPT accepts the algorithms",
		},
		{
			name: "lets encrypt rejects renewal interval",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
				"renewal_interval":          10,
			},
			wantErr: "renewal_interval is accepted",
		},
		{
			name: "lets encrypt rejects signature algorithm",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
				"signature_algorithm":       "SHA256",
			},
			wantErr: "signature_algorithm is accepted",
		},
		{
			name: "sectigo needs credentials",
			config: map[string]any{
				"certificate_provider":      "SECTIGO",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
			},
			wantErr: "ssl_provider_credentials_id is required",
		},
		{
			name: "SHA512 with ECDSA",
			config: map[string]any{
				"certificate_provider":        "DTRUST",
				"algorithm":                   "ECDSA384",
				"subject_alternative_names":   []any{"www.example.com"},
				"ssl_provider_credentials_id": 7,
				"signature_algorithm":         "SHA512",
			},
			wantErr: "SHA512 cannot be combined",
		},
		{
			name: "lets encrypt rejects credentials",
			config: map[string]any{
				"certificate_provider":        "LETS_ENCRYPT",
				"algorithm":                   "RSA2048",
				"subject_alternative_names":   []any{"www.example.com"},
				"ssl_provider_credentials_id": 7,
			},
			wantErr: "ssl_provider_credentials_id is ignored",
		},
		{
			name: "redundant subject alternative name",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"*.example.com", "www.example.com"},
			},
			wantErr: "would be dropped by the API",
		},
	}

	r := resourceMyrasecSSLCertificateRequest()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := r.Diff(context.Background(), tt.state, terraform.NewResourceConfigRaw(tt.config), nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// unknownVariableValue is the placeholder the SDK stores for values that are unknown until apply
const unknownVariableValue = "74D93920-ED26-11E3-AC10-0800200C9A66"

// TestSSLCertificateRequestStateConverges plans a request with non-canonical names, applies the
// diff, refreshes the state from the canonical API answer and expects the next plan to be empty.
func TestSSLCertificateRequestStateConverges(t *testing.T) {
	r := resourceMyrasecSSLCertificateRequest()
	ctx := context.Background()

	config := terraform.NewResourceConfigRaw(map[string]any{
		"certificate_provider":      "LETS_ENCRYPT",
		"algorithm":                 "RSA2048",
		"subject_alternative_names": []any{"WWW.Example.com.", "*.Example.org"},
		"subdomains":                []any{"WWW.Example.com."},
		"configuration_name":        "2023-mozilla-modern",
	})

	diff, err := r.Diff(ctx, nil, config, nil)
	if err != nil {
		t.Fatalf("initial plan failed: %v", err)
	}

	// MergeDiff leaves the unknown placeholder in computed attributes, the apply below
	// replaces them with the API answer like a real apply does.
	var empty *terraform.InstanceState
	applied := empty.MergeDiff(diff)
	applied.ID = "1"
	for k, v := range applied.Attributes {
		if v == unknownVariableValue {
			delete(applied.Attributes, k)
		}
	}

	d := r.Data(applied)
	setSSLCertificateRequestData(d, &myrasec.SSLCertificateRequest{
		ID:        1,
		Provider:  "LETS_ENCRYPT",
		Algorithm: "RSA2048",
		Status:    "OPEN",
		SubjectAlternativeNames: []myrasec.SSLCertificateRequestSAN{
			{ID: 10, Name: "www.example.com"},
			{ID: 11, Name: "*.example.org"},
		},
		Assignments: []myrasec.SSLCertificateRequestAssignment{
			{ID: 20, SubDomainName: "www.example.com"},
		},
	})
	refreshed := d.State()

	if got := refreshed.Attributes["configuration_name"]; got != "2023-mozilla-modern" {
		t.Errorf("configuration_name = %q after refresh, want the configured value to survive", got)
	}

	diff, err = r.Diff(ctx, refreshed, config, nil)
	if err != nil {
		t.Fatalf("second plan failed: %v", err)
	}
	if diff != nil && !diff.Empty() {
		t.Errorf("expected an empty plan after refresh, got changes: %v", diff.Attributes)
	}

	// Removing configuration_name must not plan a change either, the API keeps the profile.
	withoutProfile := terraform.NewResourceConfigRaw(map[string]any{
		"certificate_provider":      "LETS_ENCRYPT",
		"algorithm":                 "RSA2048",
		"subject_alternative_names": []any{"www.example.com", "*.example.org"},
		"subdomains":                []any{"www.example.com"},
	})
	diff, err = r.Diff(ctx, refreshed, withoutProfile, nil)
	if err != nil {
		t.Fatalf("plan without configuration_name failed: %v", err)
	}
	if diff != nil && !diff.Empty() {
		t.Errorf("expected an empty plan without configuration_name, got changes: %v", diff.Attributes)
	}
}

func TestSSLCertificateRequestSchemaValidation(t *testing.T) {
	r := resourceMyrasecSSLCertificateRequest()

	for _, valid := range []string{"LETS_ENCRYPT", "SECTIGO", "DTRUST"} {
		if _, errs := r.Schema["certificate_provider"].ValidateFunc(valid, "certificate_provider"); len(errs) > 0 {
			t.Errorf("certificate_provider %q should be valid: %v", valid, errs)
		}
	}
	if _, errs := r.Schema["certificate_provider"].ValidateFunc("lets_encrypt", "certificate_provider"); len(errs) == 0 {
		t.Error("certificate_provider should be case sensitive")
	}

	for _, valid := range []string{"RSA2048", "RSA4096", "RSA8192", "ECDSA256", "ECDSA384"} {
		if _, errs := r.Schema["algorithm"].ValidateFunc(valid, "algorithm"); len(errs) > 0 {
			t.Errorf("algorithm %q should be valid: %v", valid, errs)
		}
	}
	if _, errs := r.Schema["algorithm"].ValidateFunc("RSA1024", "algorithm"); len(errs) == 0 {
		t.Error("algorithm RSA1024 should be invalid")
	}
	if !r.Schema["algorithm"].ForceNew {
		t.Error("algorithm is immutable and has to be ForceNew")
	}

	if _, errs := r.Schema["renewal_interval"].ValidateFunc(-1, "renewal_interval"); len(errs) == 0 {
		t.Error("renewal_interval -1 should be invalid")
	}
}
