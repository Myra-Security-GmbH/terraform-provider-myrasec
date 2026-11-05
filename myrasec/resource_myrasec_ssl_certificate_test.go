package myrasec

import (
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
)

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
