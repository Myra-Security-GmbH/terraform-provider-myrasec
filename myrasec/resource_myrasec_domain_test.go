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
		{name: "verification completed before read", verified: false, readVerified: true, want: true},
		{name: "read omits verification status", verified: false, want: true},
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
			assertDomainVerificationWarning(t, diags, !tc.want)
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
			diags = r.UpdateContext(ctx, d, client)
			if diags.HasError() {
				t.Fatalf("update failed: %v", diags)
			}
			assertDomainVerificationWarning(t, diags, !tc.want)
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
	const reason = "pending domain limit reached"
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

func assertDomainVerificationWarning(t *testing.T, diags diag.Diagnostics, want bool) {
	t.Helper()
	warnings := 0
	for _, diagnostic := range diags {
		if diagnostic.Severity != diag.Warning {
			continue
		}
		warnings++
		if !strings.Contains(diagnostic.Detail, "pending or has been revoked") || !strings.Contains(diagnostic.Detail, "dashboard") {
			t.Errorf("unexpected verification warning: %v", diagnostic)
		}
	}
	if (want && warnings != 1) || (!want && warnings != 0) {
		t.Errorf("got %d warnings, want warning=%v: %v", warnings, want, diags)
	}
}

func TestDomainVerificationImportRefresh(t *testing.T) {
	for _, id := range []string{"1", "example.com"} {
		for _, tc := range domainVerificationCases {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				client := domainVerificationTestClient(t, tc.verified, tc.verified, false)
				r := resourceMyrasecDomain()
				d := r.TestResourceData()
				d.SetId(id)
				imported, err := r.Importer.StateContext(context.Background(), d, client)
				if err != nil {
					t.Fatal(err)
				}
				if len(imported) != 1 || imported[0].Id() != "1" {
					t.Fatalf("unexpected imported state: %v", imported)
				}
				// The importer cannot return warnings. Terraform reads the imported resource next.
				state, diags := r.RefreshWithoutUpgrade(context.Background(), imported[0].State(), client)
				if diags.HasError() || state == nil {
					t.Fatalf("refresh after import failed: %v", diags)
				}
				if state.Attributes["verified"] != strconv.FormatBool(tc.want) {
					t.Errorf("verified after import = %q, want %v", state.Attributes["verified"], tc.want)
				}
				assertDomainVerificationWarning(t, diags, !tc.want)
			})
		}
	}
}

func TestDomainCreateReadFailure(t *testing.T) {
	for _, autoImport := range []bool{false, true} {
		for _, tc := range domainVerificationCases {
			t.Run(tc.name+"/auto_import="+strconv.FormatBool(autoImport), func(t *testing.T) {
				client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.URL.Path == "/domains/1" {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"error":true,"violationList":[{"message":"read denied"}]}`))
						return
					}
					if r.Method == http.MethodPost && autoImport {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"error":true,"violationList":[{"message":"Domain already exists"}]}`))
						return
					}
					domain := map[string]any{"id": 1, "name": "example.com"}
					if tc.verified != nil {
						domain["verified"] = tc.verified
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{domain}})
				}))
				r := resourceMyrasecDomain()
				d := r.TestResourceData()
				if err := d.Set("name", "example.com"); err != nil {
					t.Fatal(err)
				}
				diags := r.CreateContext(context.Background(), d, client)
				if !diags.HasError() || !strings.Contains(diags[0].Detail, "read denied") {
					t.Fatalf("read error was lost: %v", diags)
				}
				if d.Id() != "1" || d.Get("verified") != tc.want {
					t.Errorf("create response was lost after read failure: id=%q verified=%v", d.Id(), d.Get("verified"))
				}
				assertDomainVerificationWarning(t, diags, !tc.want)
			})
		}
	}
}

func TestDomainReadErrorPreservesState(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		message    string
		listStatus int
		listedID   int
		fullPage   bool
		noName     bool
		removed    bool
	}{
		{name: "deleted", status: http.StatusForbidden, message: "The entity does not exist.", removed: true},
		{name: "deleted German", status: http.StatusForbidden, message: "Die Entität existiert nicht.", removed: true},
		{name: "permission denied", status: http.StatusForbidden, message: "read denied", listedID: 1},
		{name: "missing message but still listed", status: http.StatusForbidden, message: "The entity does not exist.", listedID: 1},
		{name: "list denied", status: http.StatusForbidden, message: "The entity does not exist.", listStatus: http.StatusForbidden},
		{name: "list unavailable", status: http.StatusForbidden, message: "The entity does not exist.", listStatus: http.StatusServiceUnavailable},
		{name: "name unavailable", status: http.StatusForbidden, message: "The entity does not exist.", noName: true},
		{name: "recreated with another ID", status: http.StatusForbidden, message: "The entity does not exist.", listedID: 2, removed: true},
		{name: "found on second page", status: http.StatusForbidden, message: "read denied", fullPage: true, listedID: 1},
		{name: "missing on all pages", status: http.StatusForbidden, message: "The entity does not exist.", fullPage: true, removed: true},
		{name: "server error", status: http.StatusInternalServerError, message: "server error"},
		{name: "HTTP not found", status: http.StatusNotFound, message: "not found", removed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listCalls := 0
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/domains/1":
					w.WriteHeader(tc.status)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": true, "violationList": []any{map[string]string{"message": tc.message}}})
				case "/domains":
					listCalls++
					if r.URL.Query().Get("search") != "example.com" || r.URL.Query().Get("page") != strconv.Itoa(listCalls) || r.URL.Query().Get("pageSize") != "100" {
						t.Errorf("unexpected list parameters: %s", r.URL.RawQuery)
					}
					if tc.listStatus != 0 {
						w.WriteHeader(tc.listStatus)
						_, _ = w.Write([]byte(`{"error":true,"violationList":[{"message":"listing failed"}]}`))
						return
					}
					domains := []any{}
					if tc.fullPage && listCalls == 1 {
						for id := 100; id < 200; id++ {
							domains = append(domains, map[string]any{"id": id, "name": "other.example.com"})
						}
					} else if tc.listedID != 0 {
						domains = append(domains, map[string]any{"id": tc.listedID, "name": "example.com"})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": domains})
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			r := resourceMyrasecDomain()
			d := r.TestResourceData()
			d.SetId("1")
			if !tc.noName {
				if err := d.Set("name", "example.com"); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.Set("verified", true); err != nil {
				t.Fatal(err)
			}
			diags := r.ReadContext(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("missing domain must be removed from state: id=%q diagnostics=%v", d.Id(), diags)
				}
			} else {
				if !diags.HasError() || d.Id() != "1" || d.Get("verified") != true {
					t.Fatalf("read failure must preserve state and report an error: id=%q verified=%v diagnostics=%v", d.Id(), d.Get("verified"), diags)
				}
				if !strings.Contains(diags[0].Detail, tc.message) {
					t.Errorf("original read error was lost: %v", diags)
				}
				if tc.listStatus != 0 && !strings.Contains(diags[0].Detail, "listing failed") {
					t.Errorf("list error was lost: %v", diags)
				}
			}
			wantCalls := 0
			if tc.status == http.StatusForbidden && !tc.noName {
				wantCalls = 1
				if tc.fullPage {
					wantCalls = 2
				}
			}
			if listCalls != wantCalls {
				t.Errorf("list calls = %d, want %d", listCalls, wantCalls)
			}
			assertDomainVerificationWarning(t, diags, false)
		})
	}
}
