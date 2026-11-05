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
	for _, tc := range []struct {
		name    string
		status  int
		message string
		rows    []any
		removed bool
	}{
		{name: "missing from the list", status: http.StatusOK, rows: []any{map[string]any{"id": 2, "key": "team", "value": "web"}}, removed: true},
		{name: "tag deleted", status: http.StatusForbidden, message: "The entity does not exist.", removed: true},
		{name: "HTTP not found", status: http.StatusNotFound, message: "not found", removed: true},
		{name: "forbidden with a message", status: http.StatusForbidden, message: "read denied"},
		{name: "forbidden without body", status: http.StatusForbidden},
		{name: "server error", status: http.StatusInternalServerError, message: "server error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/tags/1/information" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				if tc.status == http.StatusOK {
					_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "page": 1, "pageSize": listPageSize, "count": len(tc.rows), "data": tc.rows})
					return
				}
				if tc.message == "" {
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"error": true, "violationList": []any{map[string]string{"message": tc.message}}})
			}))
			d := tagInformationResourceData(t)
			diags := resourceMyrasecTagInformationRead(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("missing tag information was not dropped: id=%q diags=%v", d.Id(), diags)
				}
				return
			}
			want := tc.message
			if want == "" {
				want = http.StatusText(tc.status)
			}
			if !diags.HasError() || !strings.Contains(diags[0].Detail, want) {
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
