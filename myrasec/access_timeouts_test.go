package myrasec

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Exercise the SDK deadline passed to queued writes, not just the schema values.
func TestAccessWriteDeadlinesAndCancellation(t *testing.T) {
	for _, kind := range []string{"user_permission", "group_permission", "membership"} {
		for _, operation := range []string{schema.TimeoutCreate, schema.TimeoutUpdate, schema.TimeoutDelete} {
			if operation == schema.TimeoutUpdate && kind != "membership" {
				continue
			}
			for _, override := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/override=%t", kind, operation, override), func(t *testing.T) {
					r := resourceMyrasecUserPermission()
					config := map[string]any{"user_id": 1, "action": "READ", "object_type": "Domain"}
					lock := lockPermissionWrites
					if kind == "group_permission" {
						r = resourceMyrasecUserGroupPermission()
						delete(config, "user_id")
						config["group_id"] = 1
					} else if kind == "membership" {
						r = resourceMyrasecUserGroupMember()
						config = map[string]any{"group_id": 1, "user_id": 2, "role": "USER"}
						lock = lockMembershipWrites
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					unlock, err := lock(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer unlock()
					var state *terraform.InstanceState
					if operation != schema.TimeoutCreate {
						d := schema.TestResourceDataRaw(t, r.Schema, config)
						d.SetId("1:2")
						if err := d.Set("modified", "2026-10-01T00:00:00Z"); err != nil {
							t.Fatal(err)
						}
						state = d.State()
					}
					if operation == schema.TimeoutUpdate {
						config["role"] = "ADMINISTRATOR"
					}
					want := 20 * time.Minute
					if override {
						want = 5 * time.Minute
						config[schema.TimeoutsConfigKey] = map[string]any{operation: "5m"}
					}
					diffState := state
					if operation == schema.TimeoutDelete {
						diffState = nil
					}
					diff, err := r.Diff(ctx, diffState, terraform.NewResourceConfigRaw(config), nil)
					if err != nil || diff == nil {
						t.Fatalf("diff=%v error=%v", diff, err)
					}
					if operation == schema.TimeoutDelete {
						// Destroy restores timeout metadata persisted by the previous apply.
						state.Meta = diff.Meta
						diff = &terraform.InstanceDiff{Destroy: true}
					}
					var original func(context.Context, *schema.ResourceData, any) diag.Diagnostics = r.CreateContext
					if operation == schema.TimeoutUpdate {
						original = r.UpdateContext
					} else if operation == schema.TimeoutDelete {
						original = r.DeleteContext
					}
					called := false
					callback := func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
						called = true
						deadline, ok := ctx.Deadline()
						if remaining := time.Until(deadline); !ok || remaining < want-time.Second || remaining > want {
							t.Errorf("queued write deadline: got %s, want %s", remaining, want)
						}
						// Cancellation must still stop a write waiting behind the held lock.
						cancel()
						return original(ctx, d, meta)
					}
					switch operation {
					case schema.TimeoutCreate:
						r.CreateContext = callback
					case schema.TimeoutUpdate:
						r.UpdateContext = callback
					case schema.TimeoutDelete:
						r.DeleteContext = callback
					}
					_, diags := r.Apply(ctx, state, diff, nil)
					if !called || !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "context canceled") {
						t.Fatalf("called=%t diagnostics=%v", called, diags)
					}
				})
			}
		}
	}
}
