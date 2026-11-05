package myrasec

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestRedirectReadErrorPreservesState pins the read behaviour on API errors: a redirect that
// no longer exists is dropped from the state, every other error keeps the state and fails the
// run instead of planning a recreation.
func TestRedirectReadErrorPreservesState(t *testing.T) {
	for _, tc := range readErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodGet, "/domain/1/redirects/www.example.com/1", tc.status, tc.message))
			d := resourceMyrasecRedirect().TestResourceData()
			d.SetId("1")
			for k, v := range map[string]any{"subdomain_name": "www.example.com", "domain_id": 1, "source": "/old", "destination": "/new", "type": "permanent", "matching_type": "prefix"} {
				if err := d.Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			diags := resourceMyrasecRedirectRead(context.Background(), d, client)
			if tc.removed {
				if diags.HasError() || d.Id() != "" {
					t.Fatalf("missing redirect was not dropped: id=%q diags=%v", d.Id(), diags)
				}
				return
			}
			if !diags.HasError() || !strings.Contains(diags[0].Detail, wantErrorDetail(tc.status, tc.message)) {
				t.Fatalf("API error was lost: %v", diags)
			}
			if d.Id() != "1" || d.Get("source") != "/old" {
				t.Errorf("state was cleared after the API error: id=%q source=%q", d.Id(), d.Get("source"))
			}
		})
	}
}
