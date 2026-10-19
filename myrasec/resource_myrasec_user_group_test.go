package myrasec

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestUserGroupRoleLookupFailureRetainsState(t *testing.T) {
	for _, status := range []int{403, 404} {
		client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/user/groups/7" {
				accessResponse(w, []any{map[string]any{"id": 7, "name": "team", "parent": 1}})
				return
			}
			accessError(w, status, "Access denied")
		}))
		r := resourceMyrasecUserGroup()
		d := r.TestResourceData()
		d.SetId("7")
		if diags := r.ReadContext(context.Background(), d, client); !diags.HasError() || d.Id() != "7" {
			t.Fatalf("list status %d: state=%v diagnostics=%v", status, d.State(), diags)
		}
	}
}

func TestUserGroupReadRejectsRootAndMissingTreeEntry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		parent  int
		message string
	}{
		{"root", 0, "root groups cannot be managed"},
		{"missing", 1, "was not returned in the visible group tree"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/user/groups/7" {
					accessResponse(w, []any{map[string]any{"id": 7, "name": "team", "parent": tc.parent}})
					return
				}
				if tc.parent == 0 {
					t.Error("root read must stop before listing roles")
				}
				accessResponse(w, []any{map[string]any{"id": 1, "name": "root"}})
			}))
			r := resourceMyrasecUserGroup()
			d := r.TestResourceData()
			d.SetId("7")
			diags := r.ReadContext(context.Background(), d, client)
			if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), tc.message) || d.Id() != "7" {
				t.Fatalf("state=%v diagnostics=%v", d.State(), diags)
			}
		})
	}
}
