package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestTagWAFRuleReadErrorPreservesState pins the read behaviour when the parent tag cannot be
// loaded: a tag that no longer exists drops the rule from the state, every other error keeps
// the state and fails the run.
func TestTagWAFRuleReadErrorPreservesState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		message string
		removed bool
	}{
		{name: "tag deleted", status: http.StatusForbidden, message: "The entity does not exist.", removed: true},
		{name: "tag not found", status: http.StatusNotFound, message: "not found", removed: true},
		{name: "forbidden with a message", status: http.StatusForbidden, message: "read denied"},
		{name: "forbidden without body", status: http.StatusForbidden},
		{name: "server error", status: http.StatusInternalServerError, message: "server error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/tags/1" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				if tc.message == "" {
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"error": true, "violationList": []any{map[string]string{"message": tc.message}}})
			}))
			d := resourceMyrasecTagWAFRule().TestResourceData()
			d.SetId("1")
			for k, v := range map[string]any{"tag_id": 1, "name": "block", "direction": "in"} {
				if err := d.Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			diags := resourceMyrasecTagWAFRuleRead(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("rule of the missing tag was not dropped: id=%q diags=%v", d.Id(), diags)
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
			if d.Id() != "1" || d.Get("name") != "block" {
				t.Errorf("state was cleared after the API error: id=%q name=%q", d.Id(), d.Get("name"))
			}
		})
	}
}
