package myrasec

import (
	"context"
	"fmt"
	"strconv"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceMyrasecUserGroup() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecUserGroupCreate, ReadContext: resourceMyrasecUserGroupRead,
		UpdateContext: resourceMyrasecUserGroupUpdate, DeleteContext: resourceMyrasecUserGroupDelete,
		Importer: &schema.ResourceImporter{StateContext: resourceMyrasecUserGroupImport},
		Schema: map[string]*schema.Schema{
			"group_id":      {Type: schema.TypeInt, Computed: true},
			"name":          {Type: schema.TypeString, Required: true, ValidateFunc: validation.StringIsNotWhiteSpace},
			"parent_id":     accessIDSchema(false),
			"type":          {Type: schema.TypeString, Computed: true},
			"members_count": {Type: schema.TypeInt, Computed: true},
			"roles":         {Type: schema.TypeList, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"created":       {Type: schema.TypeString, Computed: true},
			"modified":      {Type: schema.TypeString, Computed: true},
		},
	}
}

func userGroupData(g *myrasec.UserGroup) map[string]any {
	return map[string]any{"group_id": g.ID, "name": g.Name, "parent_id": g.Parent, "type": g.Type,
		"members_count": g.MembersCount, "roles": g.Roles, "created": formatDateTime(g.Created), "modified": formatDateTime(g.Modified)}
}

func resourceMyrasecUserGroupCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	g, err := meta.(*myrasec.API).CreateUserGroupContext(ctx, &myrasec.UserGroup{Name: d.Get("name").(string), Parent: d.Get("parent_id").(int)})
	if err != nil {
		return diag.FromErr(userGroupCreateError(err))
	}
	if g.ID <= 0 {
		return diag.Errorf("API returned a user group without a positive ID")
	}
	d.SetId(strconv.Itoa(g.ID))
	if err := setAccessData(d, userGroupData(g)); err != nil {
		return diag.FromErr(err)
	}
	return resourceMyrasecUserGroupRead(ctx, d, meta)
}

func resourceMyrasecUserGroupRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	ids, err := parseCompositeIntID(d.Id(), 1)
	if err != nil {
		return diag.FromErr(err)
	}
	g, err := meta.(*myrasec.API).GetUserGroupContext(ctx, ids[0])
	if isNotFoundError(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	if g.Parent == 0 {
		return diag.Errorf("root groups cannot be managed; use the myrasec_user_groups data source to discover a parent_id")
	}
	values, err := userGroupDataWithRoles(ctx, meta.(*myrasec.API), g)
	if err != nil {
		return diag.FromErr(err)
	}
	return diag.FromErr(setAccessData(d, values))
}

func resourceMyrasecUserGroupUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	ids, err := parseCompositeIntID(d.Id(), 1)
	if err != nil {
		return diag.FromErr(err)
	}
	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = meta.(*myrasec.API).UpdateUserGroupContext(ctx, &myrasec.UserGroup{ID: ids[0], Modified: modified, Name: d.Get("name").(string), Parent: d.Get("parent_id").(int)})
	if err != nil {
		// Preserve the prior state after a rejected move or rename.
		for _, key := range []string{"name", "parent_id"} {
			old, _ := d.GetChange(key)
			if setErr := d.Set(key, old); setErr != nil {
				return diag.FromErr(fmt.Errorf("%w; restoring %s: %v", err, key, setErr))
			}
		}
		return diag.FromErr(err)
	}
	return resourceMyrasecUserGroupRead(ctx, d, meta)
}

func resourceMyrasecUserGroupDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	ids, err := parseCompositeIntID(d.Id(), 1)
	if err != nil {
		return diag.FromErr(err)
	}
	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = meta.(*myrasec.API).DeleteUserGroupContext(ctx, &myrasec.UserGroup{ID: ids[0], Modified: modified})
	if err != nil && !isNotFoundError(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func resourceMyrasecUserGroupImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	_, id, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, fmt.Errorf("group ID must be positive")
	}
	g, err := meta.(*myrasec.API).GetUserGroupContext(ctx, id)
	if err != nil {
		return nil, err
	}
	if g.Parent == 0 {
		return nil, fmt.Errorf("root groups cannot be imported: the API does not permit updating or deleting them; use myrasec_user_groups instead")
	}
	values, err := userGroupDataWithRoles(ctx, meta.(*myrasec.API), g)
	if err != nil {
		return nil, err
	}
	if err := setAccessData(d, values); err != nil {
		return nil, err
	}
	d.SetId(strconv.Itoa(id))
	return []*schema.ResourceData{d}, nil
}

// Single-group responses omit caller roles. Only the group tree supplies them.
func userGroupDataWithRoles(ctx context.Context, client *myrasec.API, group *myrasec.UserGroup) (map[string]any, error) {
	id := group.ID
	trees, err := listAccessPages(ctx, map[string]string{}, client.ListUserGroupsContext, func(g myrasec.UserGroup) int { return g.ID })
	if err != nil {
		return nil, fmt.Errorf("reading caller roles for group %d: %w", id, err)
	}
	var find func([]myrasec.UserGroup) *myrasec.UserGroup
	find = func(groups []myrasec.UserGroup) *myrasec.UserGroup {
		for _, g := range groups {
			if g.ID == id {
				return &g
			}
			if found := find(g.Children); found != nil {
				return found
			}
		}
		return nil
	}
	found := find(trees)
	if found == nil {
		return nil, fmt.Errorf("group %d was not returned in the visible group tree; cannot determine caller roles", id)
	}
	values := userGroupData(group)
	values["roles"] = found.Roles
	return values, nil
}
