package myrasec

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestPermissionRequestedAndEffectiveScopes(t *testing.T) {
	for _, tc := range []struct {
		recipient string
		id        int
	}{{"user_id", 7}, {"group_id", 10}, {"group_id", 11}} {
		t.Run(fmt.Sprintf("%s/%d", tc.recipient, tc.id), func(t *testing.T) {
			remote := map[string]any{"id": 8, "action": "READ", "objectType": "Domain", "objectPermissionType": permissionType(tc.recipient), "scopes": []int{88, 99}}
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					body := accessRequest(t, r)
					if !reflect.DeepEqual(body["scopes"], []any{float64(88)}) {
						t.Errorf("grant must send only requested scopes: %v", body)
					}
				}
				if r.Method == http.MethodGet && r.URL.Query().Get("page") == "1" && r.URL.Query().Get("all") != "true" {
					t.Error("scopes require all=true")
				}
				// The duplicate guard sees an empty list, later reads see the granted row.
				if _, ok := remote["created"]; !ok && r.Method == http.MethodGet {
					accessResponse(w, []any{})
					return
				}
				remote["created"] = "2026-10-01T00:00:00Z"
				accessResponse(w, []any{remote})
			}))
			r := resourcePermission(tc.recipient)
			raw := map[string]any{tc.recipient: tc.id, "action": "READ", "object_type": "Domain", "scopes": []any{88}}
			d := schema.TestResourceDataRaw(t, r.Schema, raw)
			ctx := context.Background()
			if diags := r.CreateContext(ctx, d, client); diags.HasError() {
				t.Fatal(diags)
			}
			if !reflect.DeepEqual(d.Get("scopes").(*schema.Set).List(), []any{88}) || d.Get("effective_scopes").(*schema.Set).Len() != 2 {
				t.Fatal(d.State())
			}
			remote["scopes"] = []int{99, 88}
			if diags := r.ReadContext(ctx, d, client); diags.HasError() {
				t.Fatal(diags)
			}
			diff, err := r.Diff(ctx, d.State(), terraform.NewResourceConfigRaw(raw), client)
			if err != nil || diff != nil && !diff.Empty() {
				t.Fatalf("derived scopes or ordering caused drift: %v %v", diff, err)
			}
			// Removing an explicit restriction out of band must not be hidden as a computed change.
			remote["scopes"] = []int{99}
			if diags := r.ReadContext(ctx, d, client); diags.HasError() {
				t.Fatal(diags)
			}
			diff, err = r.Diff(ctx, d.State(), terraform.NewResourceConfigRaw(raw), client)
			if err != nil || diff == nil || !diff.RequiresNew() {
				t.Fatalf("missing requested scope must plan replacement: %v %v", diff, err)
			}
		})
	}
}

func TestPermissionCreateRejectsMissingRequestedScope(t *testing.T) {
	created := false
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			created = true
		}
		if !created {
			accessResponse(w, []any{})
			return
		}
		accessResponse(w, []any{map[string]any{"id": 8, "action": "READ", "objectType": "Domain", "objectPermissionType": "GROUP", "scopes": []int{99}}})
	}))
	r := resourceMyrasecUserGroupPermission()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"group_id": 10, "action": "READ", "object_type": "Domain", "scopes": []any{88}})
	diags := r.CreateContext(context.Background(), d, client)
	if !diags.HasError() || d.Id() != "10:8" || !strings.Contains(fmt.Sprint(diags), "did not retain requested scopes [88]") {
		t.Fatalf("state=%v diagnostics=%v", d.State(), diags)
	}
}

func TestPermissionImportAdoptsEffectiveScopes(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessResponse(w, []any{map[string]any{"id": 8, "action": "READ", "objectType": "Domain", "objectPermissionType": "GROUP", "scopes": []int{88, 99}}})
	}))
	r := resourceMyrasecUserGroupPermission()
	d := r.TestResourceData()
	d.SetId("10:8")
	ctx := context.Background()
	if _, err := r.Importer.StateContext(ctx, d, client); err != nil {
		t.Fatal(err)
	}
	if d.Get("scopes").(*schema.Set).Len() != 0 || d.Get("effective_scopes").(*schema.Set).Len() != 2 {
		t.Fatal(d.State())
	}
	config := terraform.NewResourceConfigRaw(map[string]any{"group_id": 10, "action": "READ", "object_type": "Domain"})
	diff, err := r.Diff(ctx, d.State(), config, client)
	if err != nil || diff != nil && !diff.Empty() {
		t.Fatalf("import with API-managed scopes must have a clean plan: %v %v", diff, err)
	}
}

func TestPermissionCreateRejectsInvalidResponse(t *testing.T) {
	for _, recipient := range []string{"user_id", "group_id"} {
		for _, id := range []int{0, -1, 8} {
			t.Run(fmt.Sprintf("%s/%d", recipient, id), func(t *testing.T) {
				posts := 0
				client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.Method == http.MethodPost {
						posts++
						accessResponse(w, []any{map[string]any{"id": id, "action": "READ", "objectType": "Domain", "objectPermissionType": permissionType(recipient)}})
						return
					}
					accessResponse(w, []any{})
				}))
				r := resourcePermission(recipient)
				d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{recipient: 7, "action": "READ", "object_type": "Domain"})
				diags := r.CreateContext(context.Background(), d, client)
				want := "without a positive ID"
				if id > 0 {
					want = "could not be found during read-back"
				}
				if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), want) || d.Id() != "" || posts != 1 {
					t.Fatalf("state=%v posts=%d diagnostics=%v", d.State(), posts, diags)
				}
			})
		}
	}
}

func TestPermissionDeleteWaitsForWriter(t *testing.T) {
	for _, recipient := range []string{"user_id", "group_id"} {
		t.Run(recipient, func(t *testing.T) {
			unlock, err := lockPermissionWrites(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			var requests atomic.Int32
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests.Add(1)
				accessResponse(w, []any{})
			}))
			r := resourcePermission(recipient)
			d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{recipient: 7, "action": "READ", "object_type": "Domain", "modified": "2026-10-01T00:00:00Z"})
			d.SetId("7:8")
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			diags := r.DeleteContext(ctx, d, client)
			if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "context deadline exceeded") || d.Id() != "7:8" || requests.Load() != 0 {
				t.Fatalf("state=%v requests=%d diagnostics=%v", d.State(), requests.Load(), diags)
			}
		})
	}
}
