package myrasec

import (
	"context"
	"encoding/json"
	"maps"
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

func domainVerificationTestClient(t *testing.T, verified, readVerified any, autoImport bool) *myrasec.API {
	t.Helper()
	domain := map[string]any{
		"id": 1, "name": "example.com", "autoUpdate": true,
		"created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z",
	}
	if verified != nil {
		domain["verified"] = verified
	}
	return domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		response := maps.Clone(domain)
		if r.Method == http.MethodGet && r.URL.Path == "/domains/1" {
			delete(response, "verified")
			if readVerified != nil {
				response["verified"] = readVerified
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{response}})
	}))
}

func domainTestClient(t *testing.T, handler http.Handler) *myrasec.API {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := (Config{APIToken: "token", Language: "en", APIBaseURL: server.URL + "/%s", APICacheTTL: 0}).Client()
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestDomainVerificationCreate(t *testing.T) {
	cases := []struct {
		name         string
		verified     any
		readVerified any
		want         bool
		warn         bool
	}{
		{name: "verified", verified: true, readVerified: true, want: true},
		{name: "pending", verified: false, readVerified: false, warn: true},
		{name: "omitted", want: true},
		{name: "only read reports pending", readVerified: false, warn: true},
		{name: "only create or list reports pending", verified: false, want: true, warn: true},
	}
	for _, autoImport := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(tc.name+"/auto_import="+strconv.FormatBool(autoImport), func(t *testing.T) {
				client := domainVerificationTestClient(t, tc.verified, tc.readVerified, autoImport)
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
				if !tc.warn {
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
			client := domainVerificationTestClient(t, tc.verified, tc.verified, false)
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
			if err := d.Set("verified", !tc.want); err != nil {
				t.Fatal(err)
			}
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
			client := domainVerificationTestClient(t, tc.verified, tc.verified, false)
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

func TestDomainCreateFailurePreservesAPIError(t *testing.T) {
	for _, reason := range []string{
		"pending domain limit reached",
		"daily pending limit reached",
		"a create already in progress",
		"verification unavailable",
	} {
		for _, listFails := range []bool{false, true} {
			t.Run(reason+"/list_fails="+strconv.FormatBool(listFails), func(t *testing.T) {
				client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.URL.Path != "/domains" || (r.Method != http.MethodPost && r.Method != http.MethodGet) {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						http.NotFound(w, r)
						return
					}
					message := reason
					if r.Method == http.MethodGet {
						if !listFails {
							_, _ = w.Write([]byte(`{"error":false,"data":[]}`))
							return
						}
						message = "unable to list domains"
					}
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error": true, "violationList": []any{map[string]any{"message": message}},
					})
				}))
				r := resourceMyrasecDomain()
				d := r.TestResourceData()
				if err := d.Set("name", "example.com"); err != nil {
					t.Fatal(err)
				}
				diags := r.CreateContext(context.Background(), d, client)
				if len(diags) != 1 || diags[0].Severity != diag.Error {
					t.Fatalf("failed create needs an error diagnostic, got %v", diags)
				}
				if !strings.Contains(diags[0].Detail, reason) {
					t.Errorf("create error %q missing from diagnostic: %v", reason, diags)
				}
				wantImportError := "unable to find existing domain for automatic import"
				if listFails {
					wantImportError = "unable to list domains"
				}
				if !strings.Contains(diags[0].Detail, wantImportError) {
					t.Errorf("import error %q missing from diagnostic: %v", wantImportError, diags)
				}
				if d.Id() != "" {
					t.Errorf("failed create must not set an ID, got %q", d.Id())
				}
			})
		}
	}
}
