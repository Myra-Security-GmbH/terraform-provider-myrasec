package myrasec

import (
	"context"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceMyrasecUserGroups() *schema.Resource {
	fields := resourceMyrasecUserGroup().Schema
	fields["id"] = fields["group_id"]
	delete(fields, "group_id")
	fields["depth"] = &schema.Schema{
		Description: "Depth of the first matching occurrence in the visible tree, starting at zero.",
		Type:        schema.TypeInt,
		Computed:    true,
	}
	for _, field := range fields {
		field.Required = false
		field.Computed = true
		field.ValidateFunc = nil
	}
	return &schema.Resource{
		Timeouts: &schema.ResourceTimeout{
			Read: schema.DefaultTimeout(30 * time.Second),
		},
		Schema: map[string]*schema.Schema{
			"filter": accessFilterSchema(map[string]*schema.Schema{
				"name": {
					Description: "Case-sensitive substring of the group name.",
					Type:        schema.TypeString,
					Optional:    true,
				},
				"role": accessRoleSchema(false),
			}),
			"groups": {
				Description: "Visible groups flattened into a list with unique IDs.",
				Type:        schema.TypeList,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: fields,
				},
			},
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
			emitted := make(map[int]bool)
			var visit func([]myrasec.UserGroup, int)
			visit = func(nodes []myrasec.UserGroup, depth int) {
				for _, g := range nodes {
					if !emitted[g.ID] && strings.Contains(g.Name, name) {
						v := userGroupData(&g)
						v["id"] = g.ID
						delete(v, "group_id")
						v["depth"] = depth
						values = append(values, v)
						emitted[g.ID] = true
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
