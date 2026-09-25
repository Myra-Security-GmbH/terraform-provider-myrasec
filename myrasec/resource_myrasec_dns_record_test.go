package myrasec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
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

func TestDNSRecordNamesEqual(t *testing.T) {
	tests := []struct {
		old, new string
		want     bool
	}{
		{old: "www.example.com.", new: "www", want: true},
		{old: "www.example.com.", new: "www.example.com", want: true},
		{old: "www.example.com.", new: "www.example.com.", want: true},
		{old: "www.example.com.", new: "WWW.example.com", want: true},
		{old: "www.example.com.", new: "WWW", want: true},
		{old: "example.com.", new: "example.com", want: true},
		{old: "www.example.com.", new: "shop", want: false},
		{old: "www.example.com.", new: "shop.example.com", want: false},
		{old: "www.example.com.", new: "www.example.org", want: false},
		{old: "", new: "www", want: false},
	}

	for _, tt := range tests {
		if got := dnsRecordNamesEqual(tt.old, tt.new, "example.com"); got != tt.want {
			t.Errorf("dnsRecordNamesEqual(%q, %q) = %t, want %t", tt.old, tt.new, got, tt.want)
		}
	}
}

func TestDNSRecordAliasesComputedOnRename(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error": false, "page": 1, "pageSize": 50, "count": 1, "data": [{"id": 1, "name": "example.com", "reversed": false}]}`))
	}))
	defer server.Close()

	api, err := myrasec.New("key", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	api.BaseURL = server.URL + "/%s"

	state := &terraform.InstanceState{
		ID: "1",
		Attributes: map[string]string{
			"id":                       "1",
			"domain_name":              "example.com",
			"name":                     "www.example.com.",
			"value":                    "192.168.0.1",
			"record_type":              "A",
			"ttl":                      "300",
			"active":                   "true",
			"enabled":                  "true",
			"alternative_cname":        "www-example-com.ax4z.com.",
			"alternative_cname_dnssec": "www-example-com.ax4z-s.com.",
		},
	}

	tests := []struct {
		name         string
		recordName   string
		wantComputed bool
	}{
		{name: "relative name as documented", recordName: "www", wantComputed: false},
		{name: "fqdn without trailing dot", recordName: "www.example.com", wantComputed: false},
		{name: "fqdn in upper case", recordName: "WWW.example.com", wantComputed: false},
		{name: "rename to a relative name", recordName: "shop", wantComputed: true},
		{name: "rename to an fqdn", recordName: "shop.example.com", wantComputed: true},
	}

	r := resourceMyrasecDNSRecord()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := terraform.NewResourceConfigRaw(map[string]any{
				"domain_name": "example.com",
				"name":        tt.recordName,
				"value":       "192.168.0.1",
				"record_type": "A",
				"ttl":         300,
			})

			diff, err := r.Diff(context.Background(), state, config, api)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, key := range []string{"alternative_cname", "alternative_cname_dnssec"} {
				computed := diff != nil && diff.Attributes[key] != nil && diff.Attributes[key].NewComputed
				if computed != tt.wantComputed {
					t.Errorf("%s NewComputed = %t, want %t", key, computed, tt.wantComputed)
				}
			}

			if !tt.wantComputed && diff != nil && len(diff.Attributes) > 0 {
				t.Errorf("expected no diff, got %v", diff.Attributes)
			}
		})
	}
}
