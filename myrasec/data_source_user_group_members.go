package myrasec

import (
	"context"
	"strconv"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceMyrasecUserGroupMembers() *schema.Resource {
	fields := userDataSchema()
	fields["role"] = &schema.Schema{Type: schema.TypeString, Computed: true}
	fields["assignment_id"] = &schema.Schema{Type: schema.TypeInt, Computed: true}
	fields["assignment_created"] = &schema.Schema{Type: schema.TypeString, Computed: true}
	fields["assignment_modified"] = &schema.Schema{Type: schema.TypeString, Computed: true}
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"group_id": accessIDSchema(false),
			"members":  {Type: schema.TypeList, Computed: true, Elem: &schema.Resource{Schema: fields}},
		},
		ReadContext: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			id := d.Get("group_id").(int)
			users, err := listGroupMembers(ctx, meta.(*myrasec.API), id)
			if err != nil {
				return diag.FromErr(err)
			}
			values := make([]any, 0, len(users))
			for _, u := range users {
				role, err := memberRole(u, id)
				if err != nil {
					return diag.FromErr(err)
				}
				v := userData(u)
				v["role"] = role.Role
				v["assignment_id"] = role.ID
				v["assignment_created"] = formatDateTime(role.Created)
				v["assignment_modified"] = formatDateTime(role.Modified)
				values = append(values, v)
			}
			if err := d.Set("members", values); err != nil {
				return diag.FromErr(err)
			}
			d.SetId(strconv.Itoa(id))
			return nil
		},
	}
}
