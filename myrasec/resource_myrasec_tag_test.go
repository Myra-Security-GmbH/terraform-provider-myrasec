package myrasec

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestTagReadErrorPreservesState pins the read behaviour on API errors: a tag that no longer
// exists is dropped from the state, every other error keeps the state and fails the run
// instead of planning a recreation.
func TestTagReadErrorPreservesState(t *testing.T) {
	for _, tc := range readErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodGet, "/tags/1", tc.status, tc.message))
			d := resourceMyrasecTag().TestResourceData()
			d.SetId("1")
			for k, v := range map[string]any{"name": "production", "type": "CONFIG"} {
				if err := d.Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			diags := resourceMyrasecTagRead(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("missing tag was not dropped: id=%q diags=%v", d.Id(), diags)
				}
				return
			}
			if !diags.HasError() || !strings.Contains(diags[0].Detail, wantErrorDetail(tc.status, tc.message)) {
				t.Fatalf("API error was lost: %v", diags)
			}
			if d.Id() != "1" || d.Get("name") != "production" {
				t.Errorf("state was cleared after the API error: id=%q name=%q", d.Id(), d.Get("name"))
			}
		})
	}
}

// TestTagImportReportsError pins the importer: a tag that does not exist is reported as
// missing, every other API error is passed on as it is instead of being reported as a
// missing tag.
func TestTagImportReportsError(t *testing.T) {
	for _, tc := range readErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodGet, "/tags/1", tc.status, tc.message))
			r := resourceMyrasecTag()
			d := r.TestResourceData()
			d.SetId("example.com:1")
			imported, err := r.Importer.StateContext(context.Background(), d, client)
			if err == nil || imported != nil {
				t.Fatalf("import did not fail: %v", imported)
			}
			want := wantErrorDetail(tc.status, tc.message)
			if tc.removed {
				want = "unable to find tag with id [1]"
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("import error %q does not name %q", err, want)
			}
		})
	}
}
