package myrasec

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDNSRecordSchemaInternalValidate(t *testing.T) {
	if err := resourceMyrasecDNSRecord().InternalValidate(nil, true); err != nil {
		t.Fatalf("resource schema invalid: %v", err)
	}
	if err := dataSourceMyrasecDNSRecords().InternalValidate(nil, false); err != nil {
		t.Fatalf("data source schema invalid: %v", err)
	}
}

func TestDNSRecordAlternativeCNAMEDNSSECComputedOnRename(t *testing.T) {
	state := &terraform.InstanceState{
		ID: "1",
		Attributes: map[string]string{
			"id":                       "1",
			"domain_name":              "example.com",
			"name":                     "www.example.com",
			"value":                    "192.168.0.1",
			"record_type":              "A",
			"ttl":                      "300",
			"alternative_cname":        "www-example-com.ax4z.com.",
			"alternative_cname_dnssec": "www-example-com.ax4z-s.com.",
		},
	}

	tests := []struct {
		name         string
		recordName   string
		wantComputed bool
	}{
		{name: "rename marks the signed alias as known after apply", recordName: "shop.example.com", wantComputed: true},
		{name: "unchanged name keeps the signed alias", recordName: "www.example.com", wantComputed: false},
	}

	r := resourceMyrasecDNSRecord()
	r.CustomizeDiff = customdiff.ComputedIf("alternative_cname_dnssec", nameChanged)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := terraform.NewResourceConfigRaw(map[string]any{
				"domain_name": "example.com",
				"name":        tt.recordName,
				"value":       "192.168.0.1",
				"record_type": "A",
				"ttl":         300,
			})

			diff, err := r.Diff(context.Background(), state, config, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			attr := diff.Attributes["alternative_cname_dnssec"]
			computed := attr != nil && attr.NewComputed
			if computed != tt.wantComputed {
				t.Errorf("alternative_cname_dnssec NewComputed = %t, want %t", computed, tt.wantComputed)
			}
		})
	}
}
