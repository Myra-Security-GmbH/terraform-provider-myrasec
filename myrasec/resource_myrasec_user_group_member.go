package myrasec

import (
	"context"
	"fmt"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMyrasecUserGroupMember() *schema.Resource {
	return &schema.Resource{
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Read:   schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
			Delete: schema.DefaultTimeout(30 * time.Second),
		},
		CreateContext: resourceMyrasecUserGroupMemberCreate,
		UpdateContext: resourceMyrasecUserGroupMemberUpdate,
		ReadContext:   resourceMyrasecUserGroupMemberRead,
		DeleteContext: resourceMyrasecUserGroupMemberDelete,
		Importer:      &schema.ResourceImporter{StateContext: resourceMyrasecUserGroupMemberImport},
		Schema: map[string]*schema.Schema{
			"group_id": accessIDSchema("ID of the user group.", true),
			"user_id":  accessIDSchema("ID of the user.", true),
			"role":     accessRoleSchema(true),
			"assignment_id": {
				Description: "ID of the group role assignment.",
				Type:        schema.TypeInt,
				Computed:    true,
			},
			"created": {
				Description: "Creation timestamp returned by the API.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"modified": {
				Description: "Last modification timestamp returned by the API.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

// Membership writes are serialized because the API upserts rather than rejecting
// duplicate creates. Independent provider processes still require coordination.
var membershipWrites = make(chan struct{}, 1)

func lockMembershipWrites(ctx context.Context) (func(), error) {
	select {
	case membershipWrites <- struct{}{}:
		return func() { <-membershipWrites }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func resourceMyrasecUserGroupMemberCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	unlock, err := lockMembershipWrites(ctx)
	if err != nil {
		return diag.FromErr(err)
	}
	defer unlock()
	client := meta.(*myrasec.API)
	client.PruneCache()
	groupID, userID := d.Get("group_id").(int), d.Get("user_id").(int)
	members, err := listGroupMembers(ctx, client, groupID)
	if err != nil {
		return diag.FromErr(err)
	}
	for _, member := range members {
		if member.ID == userID {
			return diag.Errorf("membership already exists, import it as %d:%d", groupID, userID)
		}
	}
	return resourceMyrasecUserGroupMemberUpsert(ctx, d, meta)
}

func resourceMyrasecUserGroupMemberUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	unlock, err := lockMembershipWrites(ctx)
	if err != nil {
		return diag.FromErr(err)
	}
	defer unlock()
	return resourceMyrasecUserGroupMemberUpsert(ctx, d, meta)
}

func resourceMyrasecUserGroupMemberUpsert(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	groupID, userID := d.Get("group_id").(int), d.Get("user_id").(int)
	assignment, err := meta.(*myrasec.API).AddUserToGroupContext(ctx, &myrasec.GroupRole{UserID: userID, Role: strings.ToUpper(d.Get("role").(string))}, groupID)
	if err != nil {
		if d.Id() != "" {
			old, _ := d.GetChange("role")
			if setErr := d.Set("role", old); setErr != nil {
				return diag.FromErr(fmt.Errorf("%w; restoring role: %v", err, setErr))
			}
		}
		return diag.FromErr(err)
	}
	d.SetId(fmt.Sprintf("%d:%d", groupID, userID))
	if err := setAccessData(d, map[string]any{"assignment_id": assignment.ID,
		"created":  formatDateTime(assignment.Created),
		"modified": formatDateTime(assignment.Modified)}); err != nil {
		return diag.FromErr(err)
	}
	return resourceMyrasecUserGroupMemberRead(ctx, d, meta)
}

func resourceMyrasecUserGroupMemberRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	ids, err := parseCompositeIntID(d.Id(), 2)
	if err != nil {
		return diag.FromErr(err)
	}
	users, err := listGroupMembers(ctx, meta.(*myrasec.API), ids[0])
	if isNotFoundError(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for _, user := range users {
		if user.ID != ids[1] {
			continue
		}
		role, err := memberRole(user, ids[0])
		if err != nil {
			return diag.FromErr(err)
		}
		return diag.FromErr(setAccessData(d, map[string]any{"group_id": ids[0],
			"user_id":       ids[1],
			"role":          role.Role,
			"assignment_id": role.ID,
			"created":       formatDateTime(role.Created),
			"modified":      formatDateTime(role.Modified)}))
	}
	d.SetId("")
	return nil
}

func resourceMyrasecUserGroupMemberDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	ids, err := parseCompositeIntID(d.Id(), 2)
	if err != nil {
		return diag.FromErr(err)
	}
	unlock, err := lockMembershipWrites(ctx)
	if err != nil {
		return diag.FromErr(err)
	}
	defer unlock()
	_, err = meta.(*myrasec.API).RemoveUserFromGroupContext(ctx, &myrasec.User{ID: ids[1]}, ids[0])
	if err != nil && !isNotFoundError(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func resourceMyrasecUserGroupMemberImport(_ context.Context, d *schema.ResourceData, _ any) ([]*schema.ResourceData, error) {
	ids, err := parseCompositeIntID(d.Id(), 2)
	if err != nil {
		return nil, err
	}
	if err := setAccessData(d, map[string]any{"group_id": ids[0],
		"user_id": ids[1]}); err != nil {
		return nil, err
	}
	d.SetId(fmt.Sprintf("%d:%d", ids[0], ids[1]))
	return []*schema.ResourceData{d}, nil
}
