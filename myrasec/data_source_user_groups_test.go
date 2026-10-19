package myrasec

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net/http"
	"reflect"
	"testing"
)

func TestUserGroupsDeduplicateWithoutSkippingDescendants(t *testing.T) {
	for _, filter := range []string{"", "team"} {
		t.Run(fmt.Sprintf("filter=%s", filter), func(t *testing.T) {
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				accessResponse(w, []any{
					map[string]any{"id": 2, "name": "team child", "parent": 1},
					map[string]any{"id": 1, "name": "parent", "children": []any{
						map[string]any{"id": 2, "name": "team child", "parent": 1, "children": []any{
							map[string]any{"id": 3, "name": "team grandchild", "parent": 2},
						}},
					}},
				})
			}))
			r := dataSourceMyrasecUserGroups()
			d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"filter": []any{map[string]any{"name": filter}}})
			if diags := r.ReadContext(context.Background(), d, client); diags.HasError() {
				t.Fatal(diags)
			}
			ids, depths := []int{}, []int{}
			for _, v := range d.Get("groups").([]any) {
				row := v.(map[string]any)
				ids = append(ids, row["id"].(int))
				depths = append(depths, row["depth"].(int))
			}
			wantIDs, wantDepths := []int{2, 1, 3}, []int{0, 0, 2}
			if filter != "" {
				wantIDs, wantDepths = []int{2, 3}, []int{0, 2}
			}
			if !reflect.DeepEqual(ids, wantIDs) || !reflect.DeepEqual(depths, wantDepths) {
				t.Fatalf("IDs=%v depths=%v", ids, depths)
			}
		})
	}
}
