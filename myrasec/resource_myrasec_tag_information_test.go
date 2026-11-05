package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func tagInformationResourceData(t *testing.T) *schema.ResourceData {
	t.Helper()
	d := resourceMyrasecTagInformation().TestResourceData()
	d.SetId("1")
	for k, v := range map[string]any{"tag_id": 1, "key": "environment", "value": "production"} {
		if err := d.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// TestTagInformationReadErrorPreservesState pins the read behaviour of a resource that is
// looked up in a list: an entry missing from the list or a tag that no longer exists is
// dropped from the state, every other error keeps the state and fails the run.
func TestTagInformationReadErrorPreservesState(t *testing.T) {
	t.Run("missing from the list", func(t *testing.T) {
		client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/tags/1/information" {
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			accessResponse(w, []any{map[string]any{"id": 2, "key": "team", "value": "web"}})
		}))
		d := tagInformationResourceData(t)
		diags := resourceMyrasecTagInformationRead(context.Background(), d, client)
		if diags.HasError() || d.Id() != "" {
			t.Fatalf("missing tag information was not dropped: id=%q diags=%v", d.Id(), diags)
		}
	})
	for _, tc := range readErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodGet, "/tags/1/information", tc.status, tc.message))
			d := tagInformationResourceData(t)
			diags := resourceMyrasecTagInformationRead(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("missing tag information was not dropped: id=%q diags=%v", d.Id(), diags)
				}
				return
			}
			if !diags.HasError() || !strings.Contains(diags[0].Detail, wantErrorDetail(tc.status, tc.message)) {
				t.Fatalf("API error was lost: %v", diags)
			}
			if d.Id() != "1" || d.Get("value") != "production" {
				t.Errorf("state was cleared after the API error: id=%q value=%q", d.Id(), d.Get("value"))
			}
		})
	}
}

func TestTagInformationReadSetsState(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "page": 1, "pageSize": listPageSize, "count": 1, "data": []any{
			map[string]any{"id": 1, "key": "environment", "value": "staging", "comment": "renamed", "created": "2026-10-01T00:00:00Z", "modified": "2026-10-02T00:00:00Z"},
		}})
	}))
	d := tagInformationResourceData(t)
	if diags := resourceMyrasecTagInformationRead(context.Background(), d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if d.Get("value") != "staging" || d.Get("comment") != "renamed" || d.Get("information_id") != 1 {
		t.Errorf("state not set from the API: value=%q comment=%q id=%v", d.Get("value"), d.Get("comment"), d.Get("information_id"))
	}
}

// TestTagInformationUpdateReportsError pins that a failed update reports the API error
// instead of dereferencing the missing result.
func TestTagInformationUpdateReportsError(t *testing.T) {
	for _, tc := range updateErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodPut, "/tags/1/information/1", tc.status, tc.message))
			d := tagInformationResourceData(t)
			diags := resourceMyrasecTagInformationUpdate(context.Background(), d, client)
			if !diags.HasError() || !strings.Contains(diags[0].Detail, wantErrorDetail(tc.status, tc.message)) {
				t.Fatalf("API error was lost: %v", diags)
			}
		})
	}
}
