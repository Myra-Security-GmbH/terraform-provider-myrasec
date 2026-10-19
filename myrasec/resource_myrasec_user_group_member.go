package myrasec

import (
	"context"
	"fmt"
	"strings"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMyrasecUserGroupMember() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecUserGroupMemberUpsert, UpdateContext: resourceMyrasecUserGroupMemberUpsert,
		ReadContext: resourceMyrasecUserGroupMemberRead, DeleteContext: resourceMyrasecUserGroupMemberDelete,
		Importer: &schema.ResourceImporter{StateContext: resourceMyrasecUserGroupMemberImport},
		Schema: map[string]*schema.Schema{
			"group_id": accessIDSchema(true), "user_id": accessIDSchema(true), "role": accessRoleSchema(true),
			"assignment_id": {Type: schema.TypeInt, Computed: true},
			"created":       {Type: schema.TypeString, Computed: true}, "modified": {Type: schema.TypeString, Computed: true},
		},
	}
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
	if err := setAccessData(d, map[string]any{"assignment_id": assignment.ID, "created": formatDateTime(assignment.Created), "modified": formatDateTime(assignment.Modified)}); err != nil {
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
		return diag.FromErr(setAccessData(d, map[string]any{"group_id": ids[0], "user_id": ids[1], "role": role.Role,
			"assignment_id": role.ID, "created": formatDateTime(role.Created), "modified": formatDateTime(role.Modified)}))
	}
	d.SetId("")
	return nil
}

func resourceMyrasecUserGroupMemberDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	ids, err := parseCompositeIntID(d.Id(), 2)
	if err != nil {
		return diag.FromErr(err)
	}
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
	if err := setAccessData(d, map[string]any{"group_id": ids[0], "user_id": ids[1]}); err != nil {
		return nil, err
	}
	d.SetId(fmt.Sprintf("%d:%d", ids[0], ids[1]))
	return []*schema.ResourceData{d}, nil
}
