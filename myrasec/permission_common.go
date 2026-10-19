package myrasec

import (
	"context"
	"fmt"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var permissionActions = []string{
	myrasec.PermissionActionRead, myrasec.PermissionActionCreate, myrasec.PermissionActionEdit,
	myrasec.PermissionActionSwitch, myrasec.PermissionActionAdmin, myrasec.PermissionActionAgentMode,
	myrasec.PermissionActionUserMode, myrasec.PermissionActionCacheClear, myrasec.PermissionActionReview,
	myrasec.PermissionActionPublish, myrasec.PermissionActionLoadbalanceRead, myrasec.PermissionActionLoadbalanceEdit,
}

// Serialize check-and-grant within this provider process. The API deduplicates
// grants without reporting whether a row was created, so parallel creates could
// otherwise adopt the same row. Separate provider processes still need coordination.
var permissionWrites = make(chan struct{}, 1)

func lockPermissionWrites(ctx context.Context) (func(), error) {
	select {
	case permissionWrites <- struct{}{}:
		return func() { <-permissionWrites }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func permissionSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"permission_id":   {Type: schema.TypeInt, Computed: true},
		"action":          {Type: schema.TypeString, Required: true, ForceNew: true, ValidateFunc: validation.StringInSlice(permissionActions, false)},
		"object_type":     {Type: schema.TypeString, Required: true, ForceNew: true, ValidateFunc: validation.StringIsNotWhiteSpace},
		"object_instance": {Type: schema.TypeInt, Optional: true, ForceNew: true, ValidateFunc: validation.IntAtLeast(0)},
		// These fields describe the object and cannot be set by a permission grant.
		"name":  {Type: schema.TypeString, Computed: true},
		"value": {Type: schema.TypeString, Computed: true},
		// Requested restrictions and API-derived scope chains have different ownership.
		"scopes":           {Type: schema.TypeSet, Optional: true, ForceNew: true, Elem: &schema.Schema{Type: schema.TypeInt, ValidateFunc: validation.IntAtLeast(1)}},
		"effective_scopes": {Type: schema.TypeSet, Computed: true, Elem: &schema.Schema{Type: schema.TypeInt}},
		"created":          {Type: schema.TypeString, Computed: true}, "modified": {Type: schema.TypeString, Computed: true},
		"parents": {Type: schema.TypeList, Computed: true, Elem: &schema.Resource{Schema: map[string]*schema.Schema{
			"id": {Type: schema.TypeInt, Computed: true}, "action": {Type: schema.TypeString, Computed: true},
			"object_type": {Type: schema.TypeString, Computed: true}, "object_instance": {Type: schema.TypeInt, Computed: true},
		}}},
	}
}

func permissionData(p myrasec.ObjectPermission) map[string]any {
	parents := make([]any, 0, len(p.Parents))
	for _, parent := range p.Parents {
		parents = append(parents, map[string]any{"id": parent.ID, "action": parent.Action, "object_type": parent.ObjectType, "object_instance": parent.ObjectInstance})
	}
	return map[string]any{"permission_id": p.ID, "action": p.Action, "object_type": p.ObjectType,
		"object_instance": p.ObjectInstance, "name": p.Name, "value": p.Value, "scopes": p.Scopes,
		"created": formatDateTime(p.Created), "modified": formatDateTime(p.Modified), "parents": parents}
}

func permissionType(recipient string) string {
	if recipient == "group_id" {
		return myrasec.PermissionTypeGroup
	}
	return myrasec.PermissionTypeUser
}

func listPermissions(ctx context.Context, client *myrasec.API, recipient string, id int) ([]myrasec.ObjectPermission, error) {
	return listAccessPages(ctx, map[string]string{"all": "true"}, func(ctx context.Context, params map[string]string) ([]myrasec.ObjectPermission, error) {
		if recipient == "group_id" {
			return client.ListUserGroupPermissionsContext(ctx, id, params)
		}
		return client.ListUserPermissionsContext(ctx, id, params)
	}, func(p myrasec.ObjectPermission) int { return p.ID })
}

func resourcePermission(recipient string) *schema.Resource {
	fields := permissionSchema()
	fields[recipient] = accessIDSchema(true)
	return &schema.Resource{
		Schema: fields,
		CreateContext: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			unlock, err := lockPermissionWrites(ctx)
			if err != nil {
				return diag.FromErr(err)
			}
			defer unlock()
			// Refresh even when another provider client populated this cache before a grant.
			client := meta.(*myrasec.API)
			client.PruneCache()
			recipientID := d.Get(recipient).(int)
			rows, err := listPermissions(ctx, client, recipient, recipientID)
			if err != nil {
				return diag.FromErr(err)
			}
			p := &myrasec.ObjectPermission{Action: d.Get("action").(string), ObjectType: d.Get("object_type").(string),
				ObjectInstance: d.Get("object_instance").(int), ObjectPermissionType: permissionType(recipient)}
			requestedScopes := d.Get("scopes").(*schema.Set).List()
			for _, v := range requestedScopes {
				p.Scopes = append(p.Scopes, v.(int))
			}
			for _, row := range rows {
				if row.ObjectPermissionType == p.ObjectPermissionType && row.ObjectType == p.ObjectType && row.ObjectInstance == p.ObjectInstance && row.Action == p.Action {
					return diag.Errorf("permission already exists, import it as %d:%d", recipientID, row.ID)
				}
			}
			var created *myrasec.ObjectPermission
			if recipient == "group_id" {
				created, err = client.AddUserGroupPermissionContext(ctx, p, recipientID)
			} else {
				created, err = client.AddUserPermissionContext(ctx, p, recipientID)
			}
			if err != nil {
				return diag.FromErr(err)
			}
			if created.ID <= 0 {
				return diag.Errorf("API returned a permission without a positive ID")
			}
			d.SetId(fmt.Sprintf("%d:%d", recipientID, created.ID))
			values := permissionResourceData(*created, requestedScopes)
			if err := setAccessData(d, values); err != nil {
				return diag.FromErr(err)
			}
			if diags := readPermission(ctx, d, meta, recipient); diags.HasError() {
				return diags
			}
			if d.Id() == "" {
				return diag.Errorf("created permission %d could not be found during read-back", created.ID)
			}
			actual := d.Get("scopes").(*schema.Set)
			missing := make([]int, 0)
			for _, scope := range requestedScopes {
				if !actual.Contains(scope) {
					missing = append(missing, scope.(int))
				}
			}
			if len(missing) != 0 {
				return diag.Errorf("API did not retain requested scopes %v on permission %s; the grant still exists and may be broader than configured", missing, d.Id())
			}
			return nil
		},
		ReadContext: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			return readPermission(ctx, d, meta, recipient)
		},
		DeleteContext: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			ids, err := parseCompositeIntID(d.Id(), 2)
			if err != nil {
				return diag.FromErr(err)
			}
			modified, err := types.ParseDate(d.Get("modified").(string))
			if err != nil {
				return diag.FromErr(err)
			}
			unlock, err := lockPermissionWrites(ctx)
			if err != nil {
				return diag.FromErr(err)
			}
			defer unlock()
			p := &myrasec.ObjectPermission{ID: ids[1], Modified: modified}
			client := meta.(*myrasec.API)
			if recipient == "group_id" {
				_, err = client.RemoveUserGroupPermissionContext(ctx, p, ids[0])
			} else {
				_, err = client.RemoveUserPermissionContext(ctx, p, ids[0])
			}
			if err != nil && !isNotFoundError(err) {
				return diag.FromErr(err)
			}
			d.SetId("")
			return nil
		},
		Importer: &schema.ResourceImporter{StateContext: func(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
			ids, err := parseCompositeIntID(d.Id(), 2)
			if err != nil {
				return nil, err
			}
			rows, err := listPermissions(ctx, meta.(*myrasec.API), recipient, ids[0])
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				if row.ID != ids[1] || row.ObjectPermissionType != permissionType(recipient) {
					continue
				}
				values := permissionResourceData(row, nil)
				values[recipient] = ids[0]
				if err := setAccessData(d, values); err != nil {
					return nil, err
				}
				d.SetId(fmt.Sprintf("%d:%d", ids[0], ids[1]))
				return []*schema.ResourceData{d}, nil
			}
			return nil, fmt.Errorf("permission %d is not a direct permission of %s %d; inherited permissions must be managed on their owning group", ids[1], recipient, ids[0])
		}},
	}
}

func readPermission(ctx context.Context, d *schema.ResourceData, meta any, recipient string) diag.Diagnostics {
	ids, err := parseCompositeIntID(d.Id(), 2)
	if err != nil {
		return diag.FromErr(err)
	}
	rows, err := listPermissions(ctx, meta.(*myrasec.API), recipient, ids[0])
	if isNotFoundError(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for _, row := range rows {
		if row.ID != ids[1] || row.ObjectPermissionType != permissionType(recipient) {
			continue
		}
		// Forget a requested scope only when the API removed it. The next plan
		// then restores the configured restriction by replacing the grant.
		retained := make([]any, 0)
		for _, scope := range d.Get("scopes").(*schema.Set).List() {
			if IntInSlice(scope.(int), row.Scopes) {
				retained = append(retained, scope)
			}
		}
		values := permissionResourceData(row, retained)
		values[recipient] = ids[0]
		return diag.FromErr(setAccessData(d, values))
	}
	d.SetId("")
	return nil
}

func permissionResourceData(p myrasec.ObjectPermission, requestedScopes []any) map[string]any {
	values := permissionData(p)
	values["effective_scopes"] = p.Scopes
	values["scopes"] = requestedScopes
	return values
}

func dataSourcePermissions(recipient string) *schema.Resource {
	fields := permissionSchema()
	delete(fields, "effective_scopes")
	for _, field := range fields {
		field.Required = false
		field.Optional = false
		field.Computed = true
		field.ForceNew = false
		field.ValidateFunc = nil
	}
	fields["scopes"].Elem = &schema.Schema{Type: schema.TypeInt}
	fields["object_permission_type"] = &schema.Schema{Type: schema.TypeString, Computed: true}
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			recipient:     accessIDSchema(false),
			"filter":      accessFilterSchema(map[string]*schema.Schema{"object_type": {Type: schema.TypeString, Optional: true}}),
			"permissions": {Type: schema.TypeList, Computed: true, Elem: &schema.Resource{Schema: fields}},
		},
		ReadContext: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			id := d.Get(recipient).(int)
			rows, err := listPermissions(ctx, meta.(*myrasec.API), recipient, id)
			if err != nil {
				return diag.FromErr(err)
			}
			objectType, _ := accessFilter(d)["object_type"].(string)
			values := make([]any, 0, len(rows))
			for _, row := range rows {
				if objectType != "" && row.ObjectType != objectType {
					continue
				}
				v := permissionData(row)
				v["object_permission_type"] = row.ObjectPermissionType
				values = append(values, v)
			}
			if err := d.Set("permissions", values); err != nil {
				return diag.FromErr(err)
			}
			d.SetId(fmt.Sprintf("%s:%d:%s", recipient, id, objectType))
			return nil
		},
	}
}
