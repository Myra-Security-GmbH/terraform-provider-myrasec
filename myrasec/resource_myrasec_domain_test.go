package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Omitted status represents an API version without domain verification support.
var domainVerificationCases = []struct {
	name     string
	verified any
	want     bool
}{
	{name: "verified", verified: true, want: true},
	{name: "pending", verified: false, want: false},
	{name: "omitted", want: true},
}

func domainVerificationTestClient(t *testing.T, verified any, autoImport bool) *myrasec.API {
	t.Helper()
	domain := map[string]any{
		"id": 1, "name": "example.com", "autoUpdate": true,
		"created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z",
	}
	if verified != nil {
		domain["verified"] = verified
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/domains" && r.URL.Path != "/domains/1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if _, ok := body["verified"]; ok {
				t.Error("read-only verified must not be sent in a write request")
			}
			if r.Method == http.MethodPost && autoImport {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":true,"violationList":[{"message":"Domain already exists"}]}`))
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{domain}})
	}))
	t.Cleanup(server.Close)
	client, err := (Config{APIToken: "token", Language: "en", APIBaseURL: server.URL + "/%s", APICacheTTL: 0}).Client()
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestDomainVerificationCreate(t *testing.T) {
	for _, autoImport := range []bool{false, true} {
		for _, tc := range domainVerificationCases {
			t.Run(tc.name+"/auto_import="+strconv.FormatBool(autoImport), func(t *testing.T) {
				client := domainVerificationTestClient(t, tc.verified, autoImport)
				r := resourceMyrasecDomain()
				d := r.TestResourceData()
				if err := d.Set("name", "example.com"); err != nil {
					t.Fatal(err)
				}
				diags := r.CreateContext(context.Background(), d, client)
				if diags.HasError() {
					t.Fatalf("create failed: %v", diags)
				}
				if d.Id() != "1" || d.Get("verified") != tc.want {
					t.Fatalf("created state: id=%q verified=%v, want id=1 verified=%v", d.Id(), d.Get("verified"), tc.want)
				}
				if tc.want {
					if len(diags) != 0 {
						t.Errorf("unexpected diagnostics: %v", diags)
					}
				} else if len(diags) != 1 || diags[0].Severity != diag.Warning || !strings.Contains(diags[0].Detail, "dashboard") {
					t.Errorf("pending domain needs a dashboard warning, got %v", diags)
				}
			})
		}
	}
}

func TestDomainVerificationRefreshAndUpdate(t *testing.T) {
	for _, tc := range domainVerificationCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainVerificationTestClient(t, tc.verified, false)
			r := resourceMyrasecDomain()
			ctx := context.Background()
			// Seed the opposite status to detect stale values when the API returns false or omits it.
			state, diags := r.RefreshWithoutUpgrade(ctx, &terraform.InstanceState{
				ID: "1", Attributes: map[string]string{"verified": strconv.FormatBool(!tc.want), "paused": "false"},
			}, client)
			if diags.HasError() || state == nil {
				t.Fatalf("refresh failed: %v", diags)
			}
			if got := state.Attributes["verified"]; got != strconv.FormatBool(tc.want) {
				t.Fatalf("verified = %q, want %v", got, tc.want)
			}
			config := terraform.NewResourceConfigRaw(map[string]any{"name": "example.com", "auto_update": true})
			diff, err := r.Diff(ctx, state, config, client)
			if err != nil {
				t.Fatal(err)
			}
			if diff != nil && !diff.Empty() {
				t.Errorf("computed status must not plan changes: %v", diff.Attributes)
			}
			d := r.Data(state)
			if diags := r.UpdateContext(ctx, d, client); diags.HasError() {
				t.Fatalf("update failed: %v", diags)
			}
			if got := d.Get("verified"); got != tc.want {
				t.Errorf("verified after update = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDomainsDataSourceVerification(t *testing.T) {
	for _, tc := range domainVerificationCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainVerificationTestClient(t, tc.verified, false)
			r := dataSourceMyrasecDomains()
			d := r.TestResourceData()
			if err := d.Set("filter", []any{map[string]any{"name": "example.com"}}); err != nil {
				t.Fatal(err)
			}
			if diags := r.ReadContext(context.Background(), d, client); diags.HasError() {
				t.Fatalf("data source read failed: %v", diags)
			}
			domains := d.Get("domains").([]any)
			if len(domains) != 1 {
				t.Fatalf("got %d domains, want 1", len(domains))
			}
			if got := domains[0].(map[string]any)["verified"]; got != tc.want {
				t.Errorf("verified = %v, want %v", got, tc.want)
			}
		})
	}
}
