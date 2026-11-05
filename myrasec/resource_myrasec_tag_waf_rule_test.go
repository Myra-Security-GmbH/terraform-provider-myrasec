package myrasec

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestTagWAFRuleReadErrorPreservesState pins the read behaviour when the parent tag cannot be
// loaded: a tag that no longer exists drops the rule from the state, every other error keeps
// the state and fails the run.
func TestTagWAFRuleReadErrorPreservesState(t *testing.T) {
	for _, tc := range readErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodGet, "/tags/1", tc.status, tc.message))
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
			if !diags.HasError() || !strings.Contains(diags[0].Detail, wantErrorDetail(tc.status, tc.message)) {
				t.Fatalf("API error was lost: %v", diags)
			}
			if d.Id() != "1" || d.Get("name") != "block" {
				t.Errorf("state was cleared after the API error: id=%q name=%q", d.Id(), d.Get("name"))
			}
		})
	}
}
