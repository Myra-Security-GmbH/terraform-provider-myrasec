package myrasec

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestTagCacheSettingUpdateReportsError pins that a failed update reports the API error
// instead of dereferencing the missing result.
func TestTagCacheSettingUpdateReportsError(t *testing.T) {
	for _, tc := range updateErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, apiErrorHandler(t, http.MethodPut, "/tag/1/cache-settings/1", tc.status, tc.message))
			d := resourceMyrasecTagCacheSetting().TestResourceData()
			d.SetId("1")
			for k, v := range map[string]any{"tag_id": 1, "type": "exact", "path": "/index.html", "ttl": 60, "not_found_ttl": 10, "sort": 1} {
				if err := d.Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			diags := resourceMyrasecTagCacheSettingUpdate(context.Background(), d, client)
			if !diags.HasError() || !strings.Contains(diags[0].Detail, wantErrorDetail(tc.status, tc.message)) {
				t.Fatalf("API error was lost: %v", diags)
			}
		})
	}
}
