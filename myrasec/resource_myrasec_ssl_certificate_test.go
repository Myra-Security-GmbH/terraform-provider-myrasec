package myrasec

import (
	"testing"
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
