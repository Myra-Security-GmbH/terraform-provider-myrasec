package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func ipFilterJSON(expireDate any) map[string]any {
	return map[string]any{
		"id": 1, "value": "192.0.2.1", "type": "BLACKLIST", "enabled": true, "subDomainName": "ALL-1",
		"created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z", "expireDate": expireDate,
	}
}

func ipFilterResourceData(t *testing.T) *schema.ResourceData {
	t.Helper()
	d := resourceMyrasecIPFilter().TestResourceData()
	d.SetId("1")
	for k, v := range map[string]any{"subdomain_name": "ALL-1", "domain_id": 1, "value": "192.0.2.1", "type": "BLACKLIST"} {
		if err := d.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// TestIPFilterReadErrorPreservesState pins the read behaviour on API errors: a filter that
// no longer exists is dropped from the state, every other error keeps the state and fails
// the run instead of planning a recreation.
func TestIPFilterReadErrorPreservesState(t *testing.T) {
	cases := append(slices.Clone(readErrorCases), apiErrorCase{name: "unavailable", status: http.StatusServiceUnavailable, message: "try again later"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodGet, "/domain/1/ip-filters/ALL-1/1", tc.status, tc.message))
			d := ipFilterResourceData(t)
			diags := resourceMyrasecIPFilterRead(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("missing filter was not dropped: id=%q diags=%v", d.Id(), diags)
				}
				return
			}
			if !diags.HasError() || !strings.Contains(diags[0].Detail, wantErrorDetail(tc.status, tc.message)) {
				t.Fatalf("API error was lost: %v", diags)
			}
			if d.Id() != "1" || d.Get("value") != "192.0.2.1" {
				t.Errorf("state was cleared after the API error: id=%q value=%q", d.Id(), d.Get("value"))
			}
		})
	}
}

func TestIPFilterReadExpireDate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expireDate any
		want       string
	}{
		{name: "unset", expireDate: nil, want: ""},
		{name: "set", expireDate: "2027-01-01T00:00:00+0100", want: "2027-01-01T00:00:00+01:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{ipFilterJSON(tc.expireDate)}})
			}))
			d := ipFilterResourceData(t)
			if err := d.Set("expire_date", "2020-01-01T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
			if diags := resourceMyrasecIPFilterRead(context.Background(), d, client); diags.HasError() {
				t.Fatal(diags)
			}
			if got := d.Get("expire_date"); got != tc.want {
				t.Errorf("expire_date = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIPFilterImport covers the final read of an import: its error must fail the import
// instead of producing a resource with an empty ID.
func TestIPFilterImport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readFail bool
	}{
		{name: "success"},
		{name: "final read fails", readFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filterCalls := 0
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/domains/1":
					_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{map[string]any{"id": 1, "name": "example.com", "created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z"}}})
				case "/domain/1/ip-filters/ALL-1/1":
					filterCalls++
					if filterCalls > 1 && tc.readFail {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"error":true,"violationList":[{"message":"read denied"}]}`))
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{ipFilterJSON(nil)}})
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			r := resourceMyrasecIPFilter()
			d := r.TestResourceData()
			d.SetId("ALL-1:1")

			result, err := r.Importer.StateContext(context.Background(), d, client)
			if tc.readFail {
				if err == nil || !strings.Contains(err.Error(), "read denied") {
					t.Fatalf("read error was lost: result=%v err=%v", result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != 1 || result[0].Id() != "1" || result[0].Get("value") != "192.0.2.1" {
				t.Errorf("unexpected import result: %v", result)
			}
		})
	}
}
