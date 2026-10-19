package myrasec

import (
	"context"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceMyrasecUserGroupMembers() *schema.Resource {
	fields := userDataSchema()
	fields["role"] = &schema.Schema{
		Description: "Membership role: USER or ADMINISTRATOR.",
		Type:        schema.TypeString,
		Computed:    true,
	}
	fields["assignment_id"] = &schema.Schema{
		Description: "ID of the group role assignment.",
		Type:        schema.TypeInt,
		Computed:    true,
	}
	fields["assignment_created"] = &schema.Schema{
		Description: "Creation timestamp of the group role assignment.",
		Type:        schema.TypeString,
		Computed:    true,
	}
	fields["assignment_modified"] = &schema.Schema{
		Description: "Last modification timestamp of the group role assignment.",
		Type:        schema.TypeString,
		Computed:    true,
	}
	return &schema.Resource{
		Timeouts: &schema.ResourceTimeout{
			Read: schema.DefaultTimeout(30 * time.Second),
		},
		Schema: map[string]*schema.Schema{
			"group_id": accessIDSchema("ID of the user group.", false),
			"members": {
				Description: "Members of the group with their role assignments.",
				Type:        schema.TypeList,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: fields,
				},
			},
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
