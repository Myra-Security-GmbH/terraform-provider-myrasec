package myrasec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestSSLProviderCredentialsInternalValidate(t *testing.T) {
	if err := resourceMyrasecSSLProviderCredentials().InternalValidate(nil, true); err != nil {
		t.Fatalf("resource schema invalid: %v", err)
	}
	if err := dataSourceMyrasecSSLProviderCredentials().InternalValidate(nil, false); err != nil {
		t.Fatalf("credentials data source schema invalid: %v", err)
	}
	if err := dataSourceMyrasecSSLProviderCertificates().InternalValidate(nil, false); err != nil {
		t.Fatalf("certificates data source schema invalid: %v", err)
	}
}

func TestBuildSSLProviderCredentials(t *testing.T) {
	d := resourceMyrasecSSLProviderCredentials().TestResourceData()

	d.Set("name", "Sectigo OV")
	d.Set("certificate_provider", "SECTIGO")
	d.Set("endpoint", "https://acme.sectigo.com/v2/OV")
	d.Set("email", "pki@example.com")
	d.Set("eab_kid", "kid")
	d.Set("eab_hmac", "hmac")
	d.Set("comment", "note")
	d.Set("credentials_id", 12)
	d.Set("modified", "2026-01-02T03:04:05Z")

	credentials, err := buildSSLProviderCredentials(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if credentials.ID != 12 {
		t.Errorf("ID = %d, want 12", credentials.ID)
	}
	if credentials.Name != "Sectigo OV" {
		t.Errorf("Name = %q, want Sectigo OV", credentials.Name)
	}
	if credentials.Provider != "SECTIGO" {
		t.Errorf("Provider = %q, want SECTIGO", credentials.Provider)
	}
	if credentials.Endpoint != "https://acme.sectigo.com/v2/OV" {
		t.Errorf("Endpoint = %q", credentials.Endpoint)
	}
	if credentials.EABKid != "kid" || credentials.EABHmac != "hmac" {
		t.Errorf("EAB = (%q, %q), want (kid, hmac)", credentials.EABKid, credentials.EABHmac)
	}
	if credentials.Modified == nil || credentials.Modified.Year() != 2026 {
		t.Errorf("Modified = %v, want 2026-01-02", credentials.Modified)
	}
	if credentials.Created != nil {
		t.Errorf("Created = %v, want nil for empty state", credentials.Created)
	}
}

func TestBuildSSLProviderCredentialsIDFromResourceID(t *testing.T) {
	d := resourceMyrasecSSLProviderCredentials().TestResourceData()
	d.SetId("99")
	d.Set("name", "x")
	d.Set("certificate_provider", "DTRUST")
	d.Set("eab_kid", "kid")
	d.Set("eab_hmac", "hmac")

	credentials, err := buildSSLProviderCredentials(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if credentials.ID != 99 {
		t.Errorf("ID = %d, want 99 from resource ID", credentials.ID)
	}
}

func TestSetSSLProviderCredentialsDataKeepsSecrets(t *testing.T) {
	d := resourceMyrasecSSLProviderCredentials().TestResourceData()
	d.Set("eab_hmac", "configured-hmac")
	d.Set("private_key", "configured-key")

	setSSLProviderCredentialsData(d, &myrasec.SSLProviderCredentials{
		ID:       5,
		Name:     "n",
		Provider: "DTRUST",
		EABKid:   "kid",
	})

	if d.Id() != "5" {
		t.Errorf("Id = %q, want 5", d.Id())
	}
	if d.Get("eab_hmac").(string) != "configured-hmac" {
		t.Error("eab_hmac must keep the configured value, the API never returns it")
	}
	if d.Get("private_key").(string) != "configured-key" {
		t.Error("private_key must keep the configured value, the API never returns it")
	}
	if d.Get("created").(string) != "" {
		t.Errorf("created = %q, want empty for nil date", d.Get("created"))
	}
}

func TestSSLProviderCredentialsSchema(t *testing.T) {
	r := resourceMyrasecSSLProviderCredentials()

	if !r.Schema["certificate_provider"].ForceNew {
		t.Error("certificate_provider has to be ForceNew, the EAB credentials belong to one provider")
	}
	for _, secret := range []string{"eab_hmac", "private_key"} {
		if !r.Schema[secret].Sensitive {
			t.Errorf("%s has to be Sensitive", secret)
		}
	}
	if _, errs := r.Schema["certificate_provider"].ValidateFunc("LETS_ENCRYPT", "certificate_provider"); len(errs) == 0 {
		t.Error("LETS_ENCRYPT needs no credentials and must be rejected")
	}
}

func TestSSLProviderCredentialsCustomizeDiff(t *testing.T) {
	sectigoState := &terraform.InstanceState{
		ID: "1",
		Attributes: map[string]string{
			"id":                   "1",
			"credentials_id":       "1",
			"name":                 "Sectigo",
			"certificate_provider": "SECTIGO",
			"endpoint":             "https://acme.sectigo.com/v2/OV",
			"eab_kid":              "kid",
			"eab_hmac":             "hmac",
		},
	}

	tests := []struct {
		name    string
		state   *terraform.InstanceState
		config  map[string]any
		wantErr string
	}{
		{
			name:  "update without endpoint keeps the stored one",
			state: sectigoState,
			config: map[string]any{
				"name":                 "Sectigo renamed",
				"certificate_provider": "SECTIGO",
				"eab_kid":              "kid",
				"eab_hmac":             "hmac",
			},
		},
		{
			name: "valid sectigo with generated key pair",
			config: map[string]any{
				"name":                 "Sectigo",
				"certificate_provider": "SECTIGO",
				"endpoint":             "https://acme.sectigo.com/v2/OV",
				"eab_kid":              "kid",
				"eab_hmac":             "hmac",
			},
		},
		{
			name: "valid dtrust with own key pair",
			config: map[string]any{
				"name":                 "D-Trust",
				"certificate_provider": "DTRUST",
				"cert":                 "-----BEGIN CERTIFICATE-----",
				"private_key":          "-----BEGIN PRIVATE KEY-----",
				"eab_kid":              "kid",
				"eab_hmac":             "hmac",
			},
		},
		{
			name: "sectigo needs endpoint",
			config: map[string]any{
				"name":                 "Sectigo",
				"certificate_provider": "SECTIGO",
				"eab_kid":              "kid",
				"eab_hmac":             "hmac",
			},
			wantErr: "endpoint is required",
		},
		{
			name: "dtrust rejects email",
			config: map[string]any{
				"name":                 "D-Trust",
				"certificate_provider": "DTRUST",
				"email":                "pki@example.com",
				"eab_kid":              "kid",
				"eab_hmac":             "hmac",
			},
			wantErr: "email must be empty",
		},
		{
			name: "cert without private key",
			config: map[string]any{
				"name":                 "D-Trust",
				"certificate_provider": "DTRUST",
				"cert":                 "-----BEGIN CERTIFICATE-----",
				"eab_kid":              "kid",
				"eab_hmac":             "hmac",
			},
			wantErr: "cert and private_key have to be set together",
		},
	}

	r := resourceMyrasecSSLProviderCredentials()
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

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "plain error", err: errors.New("boom"), want: false},
		{name: "404", err: &myrasec.APIError{StatusCode: http.StatusNotFound}, want: true},
		{name: "403 without body", err: &myrasec.APIError{StatusCode: http.StatusForbidden}, want: false},
		{
			name: "403 with does-not-exist violation",
			err:  &myrasec.APIError{StatusCode: http.StatusForbidden, Violations: []*myrasec.Violation{{Path: "id", Message: "does-not-exist"}}},
			want: true,
		},
		{
			name: "wrapped",
			err:  fmt.Errorf("wrapped: %w", &myrasec.APIError{StatusCode: http.StatusNotFound}),
			want: true,
		},
		{
			name: "400 with other violation",
			err:  &myrasec.APIError{StatusCode: http.StatusBadRequest, Violations: []*myrasec.Violation{{Message: "api.error.already-modified"}}},
			want: false,
		},
		{
			name: "400 with does-not-exist refers to a referenced object",
			err:  &myrasec.APIError{StatusCode: http.StatusBadRequest, Violations: []*myrasec.Violation{{Path: "sslProviderCredentialsId", Message: "does-not-exist"}}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotFoundError(tt.err); got != tt.want {
				t.Errorf("isNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}
