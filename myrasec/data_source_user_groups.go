package myrasec

import (
	"context"
	"strings"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceMyrasecUserGroups() *schema.Resource {
	fields := resourceMyrasecUserGroup().Schema
	fields["id"] = fields["group_id"]
	delete(fields, "group_id")
	fields["depth"] = &schema.Schema{Type: schema.TypeInt, Computed: true}
	for _, field := range fields {
		field.Required = false
		field.Computed = true
		field.ValidateFunc = nil
	}
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"filter": accessFilterSchema(map[string]*schema.Schema{"name": {Type: schema.TypeString, Optional: true}, "role": accessRoleSchema(false)}),
			"groups": {Type: schema.TypeList, Computed: true, Elem: &schema.Resource{Schema: fields}},
		},
		ReadContext: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			filter := accessFilter(d)
			name, _ := filter["name"].(string)
			role, _ := filter["role"].(string)
			params := map[string]string{}
			if role != "" {
				params["role"] = strings.ToUpper(role)
			}
			groups, err := listAccessPages(ctx, params, meta.(*myrasec.API).ListUserGroupsContext, func(g myrasec.UserGroup) int { return g.ID })
			if err != nil {
				return diag.FromErr(err)
			}
			values := make([]any, 0)
			var visit func([]myrasec.UserGroup, int)
			visit = func(nodes []myrasec.UserGroup, depth int) {
				for _, g := range nodes {
					if strings.Contains(g.Name, name) {
						v := userGroupData(&g)
						v["id"] = g.ID
						delete(v, "group_id")
						v["depth"] = depth
						values = append(values, v)
					}
					visit(g.Children, depth+1)
				}
			}
			visit(groups, 0)
			if err := d.Set("groups", values); err != nil {
				return diag.FromErr(err)
			}
			d.SetId(createContentHash(name + ":" + role))
			return nil
		},
	}
}
