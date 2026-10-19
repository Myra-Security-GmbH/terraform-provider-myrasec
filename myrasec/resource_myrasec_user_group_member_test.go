package myrasec

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestMembershipCreateRejectsExistingOrUnreadableMembers(t *testing.T) {
	for _, role := range []string{"USER", "ADMINISTRATOR", "unreadable"} {
		t.Run(role, func(t *testing.T) {
			posts := 0
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					posts++
					t.Error("create must not write before ownership is known")
				}
				if role == "unreadable" {
					accessError(w, http.StatusForbidden, "Access denied")
					return
				}
				accessResponse(w, []any{map[string]any{"id": 2, "roles": []any{map[string]any{"id": 9, "groupId": 1, "role": role}}}})
			}))
			r := resourceMyrasecUserGroupMember()
			d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"group_id": 1, "user_id": 2, "role": "USER"})
			diags := r.CreateContext(context.Background(), d, client)
			want := "membership already exists, import it as 1:2"
			if role == "unreadable" {
				want = "Access denied"
			}
			if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), want) || d.Id() != "" || posts != 0 {
				t.Fatalf("state=%v posts=%d diagnostics=%v", d.State(), posts, diags)
			}
		})
	}
}

func TestConcurrentDuplicateMembershipCreates(t *testing.T) {
	var mu sync.Mutex
	exists, posts := false, 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if req.Method == http.MethodPost {
			exists = true
			posts++
			accessResponse(w, []any{map[string]any{"id": 9, "userId": 2, "role": "USER"}})
			return
		}
		if !exists {
			accessResponse(w, []any{})
			return
		}
		accessResponse(w, []any{map[string]any{"id": 2, "roles": []any{map[string]any{"id": 9, "groupId": 1, "role": "USER"}}}})
	})
	first, second := domainTestClient(t, handler), domainTestClient(t, handler)
	// Prime both independent clients before either creates the membership.
	for _, client := range []*myrasec.API{first, second} {
		client.EnableCaching()
		if _, err := listGroupMembers(context.Background(), client, 1); err != nil {
			t.Fatal(err)
		}
	}
	r := resourceMyrasecUserGroupMember()
	data := []*schema.ResourceData{
		schema.TestResourceDataRaw(t, r.Schema, map[string]any{"group_id": 1, "user_id": 2, "role": "USER"}),
		schema.TestResourceDataRaw(t, r.Schema, map[string]any{"group_id": 1, "user_id": 2, "role": "USER"}),
	}
	start := make(chan struct{})
	results := make(chan diag.Diagnostics, 2)
	for i, client := range []*myrasec.API{first, second} {
		go func() { <-start; results <- r.CreateContext(context.Background(), data[i], client) }()
	}
	close(start)
	failures := 0
	for range 2 {
		diags := <-results
		if diags.HasError() {
			failures++
			if !strings.Contains(fmt.Sprint(diags), "membership already exists, import it as 1:2") {
				t.Fatal(diags)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	owners := 0
	for _, d := range data {
		if d.Id() == "1:2" {
			owners++
		}
	}
	if failures != 1 || owners != 1 || posts != 1 {
		t.Fatalf("failures=%d owners=%d posts=%d", failures, owners, posts)
	}
}
