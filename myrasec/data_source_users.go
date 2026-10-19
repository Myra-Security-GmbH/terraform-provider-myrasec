package myrasec

import (
	"context"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func userDataSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"id": {
			Description: "ID of the user.",
			Type:        schema.TypeInt,
			Computed:    true,
		},
		"login": {
			Description: "Login name of the user.",
			Type:        schema.TypeString,
			Computed:    true,
		},
		"email": {
			Description: "Email address of the user.",
			Type:        schema.TypeString,
			Computed:    true,
		},
		"firstname": {
			Description: "First name of the user.",
			Type:        schema.TypeString,
			Computed:    true,
		},
		"lastname": {
			Description: "Last name of the user.",
			Type:        schema.TypeString,
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
		"active": {
			Description: "Whether the user account is active.",
			Type:        schema.TypeBool,
			Computed:    true,
		},
		"locked": {
			Description: "Whether the user account is locked.",
			Type:        schema.TypeBool,
			Computed:    true,
		},
		"tfa_enabled": {
			Description: "Whether two-factor authentication is enabled.",
			Type:        schema.TypeBool,
			Computed:    true,
		},
		"tfa_required": {
			Description: "Whether two-factor authentication is required.",
			Type:        schema.TypeBool,
			Computed:    true,
		},
	}
}

func userData(u myrasec.User) map[string]any {
	return map[string]any{"id": u.ID, "login": u.Login, "email": u.Email, "firstname": u.Firstname, "lastname": u.Lastname,
		"active": u.Active, "locked": u.Locked, "tfa_enabled": u.TfaEnabled, "tfa_required": u.TfaRequired,
		"created": formatDateTime(u.Created), "modified": formatDateTime(u.Modified)}
}

func dataSourceMyrasecUsers() *schema.Resource {
	return &schema.Resource{
		Timeouts: &schema.ResourceTimeout{
			Read: schema.DefaultTimeout(30 * time.Second),
		},
		Schema: map[string]*schema.Schema{
			"filter": accessFilterSchema(map[string]*schema.Schema{
				"search": {
					Description: "Search expression passed to the user listing API.",
					Type:        schema.TypeString,
					Optional:    true,
				},
			}),
			"users": {
				Description: "Users matching the search filter.",
				Type:        schema.TypeList,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: userDataSchema(),
				},
			},
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
