package myrasec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func accessResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": data})
}

func accessError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": true, "violationList": []any{map[string]any{"message": message}}})
}

func accessRequest(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("request body: %v", err)
	}
	return body
}

func TestParseCompositeIntID(t *testing.T) {
	for _, id := range []string{"", "1", "1:", ":2", "1:2:3", "-1:2", "0:2", "1:0", "1:1.5", " 1:2", "+1:2", "1:9999999999999999999999"} {
		if _, err := parseCompositeIntID(id, 2); err == nil {
			t.Errorf("accepted %q", id)
		}
	}
	got, err := parseCompositeIntID("001:42", 2)
	if err != nil || !reflect.DeepEqual(got, []int{1, 42}) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestAccessNotFoundTranslations(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 500} {
		for _, message := range []string{"api.error.does-not-exist", "does-not-exist", "The entity does not exist.", "Die Entität existiert nicht.", "Access denied", "Missing ADMINISTRATOR", "not-does-not-exist"} {
			err := fmt.Errorf("wrapped: %w", &myrasec.APIError{StatusCode: status, Violations: []*myrasec.Violation{nil, {Message: message}}})
			want := status == 404 || status == 403 && (message == "api.error.does-not-exist" || message == "does-not-exist" || message == "The entity does not exist." || message == "Die Entität existiert nicht.")
			if isNotFoundError(err) != want {
				t.Errorf("status=%d message=%q", status, message)
			}
		}
	}
}

func TestAccessSchemaValidationAndReplacement(t *testing.T) {
	provider := Provider()
	for _, tc := range []struct {
		name   string
		config map[string]any
	}{
		{"myrasec_user_group", map[string]any{"name": "test", "parent_id": 0}},
		{"myrasec_user_group_member", map[string]any{"group_id": 1, "user_id": 0, "role": "USER"}},
		{"myrasec_user_group_member", map[string]any{"group_id": 1, "user_id": 2, "role": "OWNER"}},
		{"myrasec_user_permission", map[string]any{"user_id": 1, "action": "BAD", "object_type": "Domain"}},
		{"myrasec_user_permission", map[string]any{"user_id": 1, "action": "READ", "object_type": "Domain", "scopes": []any{0}}},
	} {
		if diags := provider.ValidateResource(tc.name, terraform.NewResourceConfigRaw(tc.config)); !diags.HasError() {
			t.Errorf("accepted invalid config: %s %v", tc.name, tc.config)
		}
	}
	r := resourceMyrasecUserGroupMember()
	state := &terraform.InstanceState{ID: "1:2", Attributes: map[string]string{"group_id": "1", "user_id": "2", "role": "USER"}}
	config := terraform.NewResourceConfigRaw(map[string]any{"group_id": 1, "user_id": 2, "role": "administrator"})
	if diags := provider.ValidateResource("myrasec_user_group_member", config); diags.HasError() {
		t.Fatal(diags)
	}
	diff, err := r.Diff(context.Background(), state, config, nil)
	if err != nil || diff == nil || diff.RequiresNew() || diff.Attributes["role"].New != "ADMINISTRATOR" {
		t.Fatalf("role update must be in place and normalized: %v %v", diff, err)
	}
	for _, r := range []*schema.Resource{resourceMyrasecUserPermission(), resourceMyrasecUserGroupPermission()} {
		for _, key := range []string{"action", "object_type", "object_instance", "scopes"} {
			if !r.Schema[key].ForceNew {
				t.Errorf("%s must replace permission", key)
			}
		}
		if !r.Schema["name"].Computed || r.Schema["name"].Optional || !r.Schema["value"].Computed {
			t.Fatal("object metadata must be read-only")
		}
	}
}

func TestUserGroupLifecycle(t *testing.T) {
	group := map[string]any{"id": 7, "name": "team", "parent": 1, "type": "USER", "membersCount": 0, "modified": "2026-10-01T00:00:00Z"}
	var methods []string
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Method == http.MethodGet && r.URL.Path == "/user/groups" {
			listed := make(map[string]any, len(group)+1)
			for key, value := range group {
				listed[key] = value
			}
			listed["roles"] = []string{"ADMINISTRATOR"}
			accessResponse(w, []any{map[string]any{"id": 1, "parent": 0, "children": []any{listed}}})
			return
		}
		if r.URL.Path != "/user/groups" && r.URL.Path != "/user/groups/7" {
			t.Errorf("path %s", r.URL.Path)
		}
		switch r.Method {
		case http.MethodPost:
			body := accessRequest(t, r)
			if body["name"] != "team" || body["parent"] != float64(1) {
				t.Errorf("create body %v", body)
			}
		case http.MethodPut:
			body := accessRequest(t, r)
			if body["modified"] != "2026-10-01T00:00:00Z" {
				t.Errorf("missing optimistic lock: %v", body)
			}
			group["name"], group["parent"] = body["name"], body["parent"]
		case http.MethodDelete:
			body := accessRequest(t, r)
			if body["id"] != float64(7) || body["modified"] != "2026-10-01T00:00:00Z" {
				t.Errorf("delete body %v", body)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		accessResponse(w, []any{group})
	}))
	r := resourceMyrasecUserGroup()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "team", "parent_id": 1})
	ctx := context.Background()
	if diags := r.CreateContext(ctx, d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if d.Id() != "7" || d.Get("group_id") != 7 || d.Get("roles.0") != "ADMINISTRATOR" {
		t.Fatalf("created state: %v", d.State())
	}
	_ = d.Set("name", "renamed")
	_ = d.Set("parent_id", 2)
	if diags := r.UpdateContext(ctx, d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if d.Get("name") != "renamed" || d.Get("parent_id") != 2 {
		t.Fatal("update not read back")
	}
	imported := r.TestResourceData()
	imported.SetId("informational:7")
	if _, err := r.Importer.StateContext(ctx, imported, client); err != nil {
		t.Fatal(err)
	}
	if imported.Id() != "7" || imported.Get("parent_id") != 2 || imported.Get("roles.0") != "ADMINISTRATOR" {
		t.Fatal("bad imported state")
	}
	if diags := r.DeleteContext(ctx, d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if d.Id() != "" || !reflect.DeepEqual(methods, []string{"POST", "GET", "GET", "PUT", "GET", "GET", "GET", "GET", "DELETE"}) {
		t.Fatalf("id=%s methods=%v", d.Id(), methods)
	}
}

func TestUserGroupImportAndCreateErrors(t *testing.T) {
	r := resourceMyrasecUserGroup()
	for _, id := range []string{"7", "team:0", "team:-1", "team:invalid"} {
		d := r.TestResourceData()
		d.SetId(id)
		if _, err := r.Importer.StateContext(context.Background(), d, nil); err == nil {
			t.Errorf("accepted %s", id)
		}
	}
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		accessResponse(w, []any{map[string]any{"id": 1, "parent": 0, "name": "root"}})
	}))
	d := r.TestResourceData()
	d.SetId("root:1")
	if _, err := r.Importer.StateContext(context.Background(), d, client); err == nil || !strings.Contains(err.Error(), "root groups") {
		t.Fatalf("root import: %v", err)
	}
	d = schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "team", "parent_id": 1})
	diags := r.CreateContext(context.Background(), d, client)
	if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "ADMINISTRATOR") || d.Id() != "" {
		t.Fatalf("create 403: %v", diags)
	}
}

func TestUserGroupRejectedMovePreservesState(t *testing.T) {
	r := resourceMyrasecUserGroup()
	state := &terraform.InstanceState{ID: "7", Attributes: map[string]string{"name": "old", "parent_id": "1", "modified": "2026-10-01T00:00:00Z"}}
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { accessError(w, 400, "group loop") }))
	config := terraform.NewResourceConfigRaw(map[string]any{"name": "new", "parent_id": 8})
	diff, err := r.Diff(context.Background(), state, config, client)
	if err != nil {
		t.Fatal(err)
	}
	next, diags := r.Apply(context.Background(), state, diff, client)
	if !diags.HasError() || next == nil || next.Attributes["parent_id"] != "1" || next.Attributes["name"] != "old" {
		t.Fatalf("state=%v diags=%v", next, diags)
	}
}

func TestMembershipUpsertReadAndDelete(t *testing.T) {
	currentRole := "USER"
	removed := false
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/group/10/users" && r.URL.Path != "/user/group/10/users/20" {
			t.Errorf("path: %s", r.URL.Path)
		}
		switch r.Method {
		case http.MethodPost:
			body := accessRequest(t, r)
			if body["userId"] != float64(20) {
				t.Errorf("body %v", body)
			}
			currentRole = body["role"].(string)
			accessResponse(w, []any{map[string]any{"id": 30, "userId": 20, "role": currentRole}})
		case http.MethodGet:
			if r.URL.Query().Get("includeRoles") != "true" || r.URL.Query().Get("pageSize") != "250" {
				t.Errorf("query %s", r.URL.RawQuery)
			}
			users := []any{}
			if !removed {
				users = append(users, map[string]any{"id": 20, "roles": []any{map[string]any{"id": 99, "groupId": 11, "role": "USER"}, map[string]any{"id": 30, "groupId": 10, "role": currentRole, "modified": "2026-10-01T00:00:00Z"}}})
			}
			accessResponse(w, users)
		case http.MethodDelete:
			removed = true
			w.WriteHeader(204)
		}
	}))
	r := resourceMyrasecUserGroupMember()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"group_id": 10, "user_id": 20, "role": "USER"})
	ctx := context.Background()
	if diags := r.CreateContext(ctx, d, client); diags.HasError() {
		t.Fatal(diags)
	}
	_ = d.Set("role", "ADMINISTRATOR")
	if diags := r.UpdateContext(ctx, d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if d.Get("role") != "ADMINISTRATOR" || d.Get("assignment_id") != 30 {
		t.Fatalf("state %v", d.State())
	}
	ds := dataSourceMyrasecUserGroupMembers()
	dsd := schema.TestResourceDataRaw(t, ds.Schema, map[string]any{"group_id": 10})
	if diags := ds.ReadContext(ctx, dsd, client); diags.HasError() {
		t.Fatal(diags)
	}
	if dsd.Get("members.0.role") != "ADMINISTRATOR" || dsd.Get("members.0.assignment_id") != 30 {
		t.Fatal(dsd.State())
	}
	imported := r.TestResourceData()
	imported.SetId("010:020")
	if _, err := r.Importer.StateContext(ctx, imported, nil); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(ctx, imported, client); diags.HasError() {
		t.Fatal(diags)
	}
	if imported.Id() != "10:20" || imported.Get("role") != "ADMINISTRATOR" {
		t.Fatal(imported.State())
	}
	if diags := r.DeleteContext(ctx, d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if diags := r.ReadContext(ctx, imported, client); diags.HasError() || imported.Id() != "" {
		t.Fatalf("missing membership: %v", diags)
	}
}

func TestAccessReadAndDeleteNotFoundVersusForbidden(t *testing.T) {
	for _, resource := range []struct {
		name, id string
		r        *schema.Resource
	}{
		{"group", "7", resourceMyrasecUserGroup()}, {"member", "7:8", resourceMyrasecUserGroupMember()},
		{"user permission", "7:8", resourceMyrasecUserPermission()}, {"group permission", "7:8", resourceMyrasecUserGroupPermission()},
	} {
		for _, message := range []string{"The entity does not exist.", "Die Entität existiert nicht.", "Access denied"} {
			for _, op := range []string{"read", "delete"} {
				t.Run(resource.name+message+op, func(t *testing.T) {
					client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { accessError(w, 403, message) }))
					d := resource.r.TestResourceData()
					d.SetId(resource.id)
					var run func(context.Context, *schema.ResourceData, any) diag.Diagnostics = resource.r.ReadContext
					if op == "delete" {
						run = resource.r.DeleteContext
					}
					diags := run(context.Background(), d, client)
					forbidden := message == "Access denied"
					if diags.HasError() != forbidden || (d.Id() != "") != forbidden {
						t.Fatalf("id=%s diags=%v", d.Id(), diags)
					}
				})
			}
		}
	}
}

func TestAccessRejectedDeleteRetainsState(t *testing.T) {
	for _, r := range []*schema.Resource{resourceMyrasecUserGroup(), resourceMyrasecUserGroupMember()} {
		client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { accessError(w, 400, "group still has members") }))
		d := r.TestResourceData()
		id := "7"
		if _, ok := r.Schema["user_id"]; ok {
			id = "7:8"
		}
		d.SetId(id)
		if diags := r.DeleteContext(context.Background(), d, client); !diags.HasError() || d.Id() != id {
			t.Fatalf("id=%s diags=%v", d.Id(), diags)
		}
	}
}

func TestPermissionLifecycleAndImplicitScopes(t *testing.T) {
	for _, recipient := range []string{"user_id", "group_id"} {
		t.Run(recipient, func(t *testing.T) {
			path := "/user/7/permissions"
			if recipient == "group_id" {
				path = "/user/group/7/permissions"
			}
			rows := []any{}
			posts := 0
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != path && r.URL.Path != path+"/8" {
					t.Errorf("path %s", r.URL.Path)
				}
				switch r.Method {
				case http.MethodGet:
					if r.URL.Query().Get("all") != "true" {
						t.Error("scoped permissions would be hidden")
					}
					accessResponse(w, rows)
				case http.MethodPost:
					posts++
					body := accessRequest(t, r)
					if body["objectPermissionType"] != permissionType(recipient) || body["action"] != "EDIT" {
						t.Errorf("body %v", body)
					}
					if _, ok := body["name"]; ok {
						t.Error("name sent on create")
					}
					body["id"] = 8
					body["name"] = "object display name"
					body["value"] = "object value"
					body["scopes"] = []int{50}
					body["modified"] = "2026-10-01T00:00:00Z"
					rows = []any{map[string]any{"id": 9, "action": "READ", "objectType": "Domain", "objectInstance": 11, "objectPermissionType": permissionType(recipient)}, body}
					accessResponse(w, []any{body})
				case http.MethodDelete:
					body := accessRequest(t, r)
					if body["id"] != float64(8) || body["modified"] != "2026-10-01T00:00:00Z" {
						t.Errorf("delete body %v", body)
					}
					rows = rows[:1]
					w.WriteHeader(204)
				}
			}))
			r := resourcePermission(recipient)
			raw := map[string]any{recipient: 7, "action": "EDIT", "object_type": "Domain", "object_instance": 11}
			d := schema.TestResourceDataRaw(t, r.Schema, raw)
			ctx := context.Background()
			if diags := r.CreateContext(ctx, d, client); diags.HasError() {
				t.Fatal(diags)
			}
			if d.Id() != "7:8" || d.Get("name") != "object display name" || d.Get("effective_scopes").(*schema.Set).Len() != 1 || d.Get("scopes").(*schema.Set).Len() != 0 {
				t.Fatal(d.State())
			}
			diff, err := r.Diff(ctx, d.State(), terraform.NewResourceConfigRaw(raw), client)
			if err != nil || diff != nil && !diff.Empty() {
				t.Fatalf("implicit scopes and metadata must not cause drift: %v %v", diff, err)
			}
			imported := r.TestResourceData()
			imported.SetId("7:8")
			if _, err := r.Importer.StateContext(ctx, imported, client); err != nil {
				t.Fatal(err)
			}
			duplicate := schema.TestResourceDataRaw(t, r.Schema, raw)
			diags := r.CreateContext(ctx, duplicate, client)
			if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "import it as 7:8") || posts != 1 || duplicate.Id() != "" {
				t.Fatalf("duplicate: %v posts=%d", diags, posts)
			}
			if diags := r.DeleteContext(ctx, d, client); diags.HasError() {
				t.Fatal(diags)
			}
			if diags := r.ReadContext(ctx, imported, client); diags.HasError() || imported.Id() != "" {
				t.Fatalf("cascade/missing row: %v", diags)
			}
		})
	}
}

func TestUserPermissionDoesNotAdoptInheritedGroupPermission(t *testing.T) {
	inherited := map[string]any{"id": 8, "action": "READ", "objectType": "Domain", "objectPermissionType": "GROUP"}
	rows := []any{inherited}
	posts := 0
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			body := accessRequest(t, r)
			body["id"] = 9
			rows = append(rows, body)
			accessResponse(w, []any{body})
			return
		}
		accessResponse(w, rows)
	}))
	r := resourceMyrasecUserPermission()
	d := r.TestResourceData()
	d.SetId("7:8")
	if _, err := r.Importer.StateContext(context.Background(), d, client); err == nil {
		t.Fatal("imported inherited group permission")
	}
	d = schema.TestResourceDataRaw(t, r.Schema, map[string]any{"user_id": 7, "action": "READ", "object_type": "Domain"})
	if diags := r.CreateContext(context.Background(), d, client); diags.HasError() || d.Id() != "7:9" || posts != 1 {
		t.Fatalf("direct grant: %v", diags)
	}
}

func TestConcurrentDuplicatePermissionCreates(t *testing.T) {
	rows := []any{}
	posts := 0
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			body := accessRequest(t, r)
			body["id"] = 9
			rows = []any{body}
		}
		accessResponse(w, rows)
	}))
	client.EnableCaching()
	r := resourceMyrasecUserPermission()
	var wg sync.WaitGroup
	results := make(chan diag.Diagnostics, 2)
	for i := 0; i < 2; i++ {
		d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"user_id": 7, "action": "READ", "object_type": "Domain"})
		wg.Add(1)
		go func() { defer wg.Done(); results <- r.CreateContext(context.Background(), d, client) }()
	}
	wg.Wait()
	close(results)
	failures := 0
	for diags := range results {
		if diags.HasError() {
			failures++
		}
	}
	if failures != 1 || posts != 1 {
		t.Fatalf("failures=%d posts=%d", failures, posts)
	}
}

func TestPermissionLockCancellation(t *testing.T) {
	unlock, err := lockPermissionWrites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lockPermissionWrites(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestAccessPaginationAndUnpagedPermissions(t *testing.T) {
	for _, unpaged := range []bool{false, true} {
		t.Run(strconv.FormatBool(unpaged), func(t *testing.T) {
			calls := 0
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls > 3 {
					t.Error("pagination did not stop")
					accessResponse(w, []any{})
					return
				}
				if r.URL.Query().Get("all") != "true" || r.URL.Query().Get("pageSize") != "250" {
					t.Errorf("query %v", r.URL.Query())
				}
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				rows := []any{}
				count := 250
				start := 1
				if !unpaged && page == 2 {
					count = 1
					start = 251
				}
				for i := 0; i < count; i++ {
					rows = append(rows, map[string]any{"id": start + i, "objectPermissionType": "GROUP"})
				}
				accessResponse(w, rows)
			}))
			rows, err := listPermissions(context.Background(), client, "group_id", 7)
			want := 251
			if unpaged {
				want = 250
			}
			if err != nil || len(rows) != want || calls != 2 {
				t.Fatalf("rows=%d calls=%d err=%v", len(rows), calls, err)
			}
		})
	}
}

func TestUsersAndGroupTreeDataSources(t *testing.T) {
	for _, testGroups := range []bool{false, true} {
		t.Run(strconv.FormatBool(testGroups), func(t *testing.T) {
			calls := 0
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				if r.URL.Query().Get("pageSize") != "250" {
					t.Error("missing page size")
				}
				rows := []any{}
				if testGroups {
					if r.URL.Path != "/user/groups" || r.URL.Query().Get("role") != "ADMINISTRATOR" {
						t.Errorf("request %v", r.URL)
					}
					if page == 1 {
						for i := 1; i <= 250; i++ {
							rows = append(rows, map[string]any{"id": i, "name": "root"})
						}
					} else {
						rows = append(rows, map[string]any{"id": 251, "name": "parent", "children": []any{map[string]any{"id": 252, "name": "child", "parent": 251, "children": []any{map[string]any{"id": 253, "name": "match", "parent": 252}}}}})
					}
				} else {
					if r.URL.Path != "/users" || r.URL.Query().Get("search") != "operator" {
						t.Errorf("request %v", r.URL)
					}
					if page == 1 {
						for i := 1; i <= 250; i++ {
							rows = append(rows, map[string]any{"id": i})
						}
					} else {
						rows = append(rows, map[string]any{"id": 251, "login": "operator", "tfaEnabled": true})
					}
				}
				accessResponse(w, rows)
			}))
			r := dataSourceMyrasecUsers()
			filter := map[string]any{"search": "operator"}
			if testGroups {
				r = dataSourceMyrasecUserGroups()
				filter = map[string]any{"name": "match", "role": "ADMINISTRATOR"}
			}
			d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"filter": []any{filter}})
			if diags := r.ReadContext(context.Background(), d, client); diags.HasError() {
				t.Fatal(diags)
			}
			if calls != 2 {
				t.Fatalf("calls=%d", calls)
			}
			if testGroups {
				if d.Get("groups.#") != 1 || d.Get("groups.0.id") != 253 || d.Get("groups.0.depth") != 2 || d.Get("groups.0.parent_id") != 252 {
					t.Fatal(d.State())
				}
			} else if d.Get("users.#") != 251 || d.Get("users.250.login") != "operator" || d.Get("users.250.tfa_enabled") != true {
				t.Fatal(d.State())
			}
		})
	}
}

func TestPermissionDataSourceFilterAndRecipientType(t *testing.T) {
	for _, recipient := range []string{"user_id", "group_id"} {
		client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("all") != "true" {
				t.Error("missing all=true")
			}
			accessResponse(w, []any{map[string]any{"id": 1, "objectType": "Domain", "objectPermissionType": "GROUP", "scopes": []int{8}}, map[string]any{"id": 2, "objectType": "DnsRecord", "objectPermissionType": "USER"}})
		}))
		r := dataSourcePermissions(recipient)
		d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{recipient: 7, "filter": []any{map[string]any{"object_type": "Domain"}}})
		if diags := r.ReadContext(context.Background(), d, client); diags.HasError() {
			t.Fatal(diags)
		}
		if d.Get("permissions.#") != 1 || d.Get("permissions.0.permission_id") != 1 || d.Get("permissions.0.object_permission_type") != "GROUP" || d.Get("permissions.0.scopes").(*schema.Set).Len() != 1 {
			t.Fatal(d.State())
		}
	}
}

func TestMemberPaginationFindsSecondPage(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("includeRoles") != "true" {
			t.Error("roles required")
		}
		rows := []any{}
		page := r.URL.Query().Get("page")
		if page == "1" {
			for i := 1; i <= 250; i++ {
				rows = append(rows, map[string]any{"id": i})
			}
		} else {
			rows = append(rows, map[string]any{"id": 300, "roles": []any{map[string]any{"id": 9, "groupId": 7, "role": "USER"}}})
		}
		accessResponse(w, rows)
	}))
	r := resourceMyrasecUserGroupMember()
	d := r.TestResourceData()
	d.SetId("7:300")
	if diags := r.ReadContext(context.Background(), d, client); diags.HasError() || d.Id() != "7:300" || d.Get("role") != "USER" {
		t.Fatalf("state %v diags=%v", d.State(), diags)
	}
}

func TestMembershipRejectedRoleUpdatePreservesState(t *testing.T) {
	r := resourceMyrasecUserGroupMember()
	state := &terraform.InstanceState{ID: "7:8", Attributes: map[string]string{"group_id": "7", "user_id": "8", "role": "USER"}}
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { accessError(w, 403, "Access denied") }))
	config := terraform.NewResourceConfigRaw(map[string]any{"group_id": 7, "user_id": 8, "role": "ADMINISTRATOR"})
	diff, err := r.Diff(context.Background(), state, config, client)
	if err != nil {
		t.Fatal(err)
	}
	next, diags := r.Apply(context.Background(), state, diff, client)
	if !diags.HasError() || next == nil || next.Attributes["role"] != "USER" || next.ID != "7:8" {
		t.Fatalf("state=%v diags=%v", next, diags)
	}
}

func TestMembershipMissingOrAmbiguousRoleDoesNotForgetMembership(t *testing.T) {
	for _, roles := range [][]myrasec.UserRole{nil, {{ID: 1, GroupID: 7, Role: "USER"}, {ID: 2, GroupID: 7, Role: "ADMINISTRATOR"}}} {
		client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			accessResponse(w, []myrasec.User{{ID: 8, Roles: roles}})
		}))
		r := resourceMyrasecUserGroupMember()
		d := r.TestResourceData()
		d.SetId("7:8")
		if diags := r.ReadContext(context.Background(), d, client); !diags.HasError() || d.Id() != "7:8" {
			t.Fatalf("state=%v diags=%v", d.State(), diags)
		}
	}
}

func TestAccessReadCancellation(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { t.Error("canceled read sent a request") }))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := resourceMyrasecUserPermission()
	d := r.TestResourceData()
	d.SetId("7:8")
	if diags := r.ReadContext(ctx, d, client); !diags.HasError() || d.Id() != "7:8" {
		t.Fatalf("state=%v diags=%v", d.State(), diags)
	}
}

func TestPermissionDuplicateGuardRefreshesIndependentClientCache(t *testing.T) {
	rows := []any{}
	posts := 0
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			body := accessRequest(t, r)
			body["id"] = 9
			rows = []any{body}
		}
		accessResponse(w, rows)
	}))
	other, err := (Config{APIToken: "token", Language: "en", APIBaseURL: client.BaseURL, APICacheTTL: 30}).Client()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := listPermissions(context.Background(), other, "user_id", 7); err != nil {
		t.Fatal(err)
	}
	r := resourceMyrasecUserPermission()
	raw := map[string]any{"user_id": 7, "action": "READ", "object_type": "Domain"}
	first := schema.TestResourceDataRaw(t, r.Schema, raw)
	if diags := r.CreateContext(context.Background(), first, client); diags.HasError() {
		t.Fatal(diags)
	}
	second := schema.TestResourceDataRaw(t, r.Schema, raw)
	diags := r.CreateContext(context.Background(), second, other)
	if !diags.HasError() || posts != 1 || second.Id() != "" {
		t.Fatalf("duplicate after cached empty list: %v, posts=%d", diags, posts)
	}
}
