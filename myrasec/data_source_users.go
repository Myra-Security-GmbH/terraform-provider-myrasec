package myrasec

import (
	"context"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func userDataSchema() map[string]*schema.Schema {
	fields := map[string]*schema.Schema{"id": {Type: schema.TypeInt, Computed: true}}
	for _, key := range []string{"login", "email", "firstname", "lastname", "created", "modified"} {
		fields[key] = &schema.Schema{Type: schema.TypeString, Computed: true}
	}
	for _, key := range []string{"active", "locked", "tfa_enabled", "tfa_required"} {
		fields[key] = &schema.Schema{Type: schema.TypeBool, Computed: true}
	}
	return fields
}

func userData(u myrasec.User) map[string]any {
	return map[string]any{"id": u.ID, "login": u.Login, "email": u.Email, "firstname": u.Firstname, "lastname": u.Lastname,
		"active": u.Active, "locked": u.Locked, "tfa_enabled": u.TfaEnabled, "tfa_required": u.TfaRequired,
		"created": formatDateTime(u.Created), "modified": formatDateTime(u.Modified)}
}

func dataSourceMyrasecUsers() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"filter": accessFilterSchema(map[string]*schema.Schema{"search": {Type: schema.TypeString, Optional: true}}),
			"users":  {Type: schema.TypeList, Computed: true, Elem: &schema.Resource{Schema: userDataSchema()}},
		},
		ReadContext: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			search, _ := accessFilter(d)["search"].(string)
			params := map[string]string{}
			if search != "" {
				params["search"] = search
			}
			users, err := listAccessPages(ctx, params, meta.(*myrasec.API).ListUsersContext, func(u myrasec.User) int { return u.ID })
			if err != nil {
				return diag.FromErr(err)
			}
			values := make([]any, 0, len(users))
			for _, u := range users {
				values = append(values, userData(u))
			}
			if err := d.Set("users", values); err != nil {
				return diag.FromErr(err)
			}
			d.SetId(createContentHash(search))
			return nil
		},
	}
}
