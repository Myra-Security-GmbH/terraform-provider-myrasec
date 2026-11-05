package myrasec

import (
	"context"
	"fmt"
	"strings"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// listAccessPages collects every page of a permission endpoint, see forEachPage. Access
// records always carry an ID, a record without one is an error.
func listAccessPages[T any](ctx context.Context, params map[string]string, fetch func(context.Context, map[string]string) ([]T, error), id func(T) int) ([]T, error) {
	rows, err := listPages(params, id, func(params map[string]string) ([]T, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows, err := fetch(ctx, params)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if id(row) <= 0 {
				return nil, fmt.Errorf("API returned an access record without a positive ID")
			}
		}
		return rows, nil
	})
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = make([]T, 0)
	}
	return rows, nil
}

func accessIDSchema(description string, forceNew bool) *schema.Schema {
	return &schema.Schema{
		Description:  description,
		Type:         schema.TypeInt,
		Required:     true,
		ForceNew:     forceNew,
		ValidateFunc: validation.IntAtLeast(1),
	}
}

func accessRoleSchema(required bool) *schema.Schema {
	return &schema.Schema{
		Description:  "Membership role: USER or ADMINISTRATOR.",
		Type:         schema.TypeString,
		Required:     required,
		Optional:     !required,
		StateFunc:    func(v any) string { return strings.ToUpper(v.(string)) },
		ValidateFunc: validation.StringInSlice([]string{myrasec.GroupRoleUser, myrasec.GroupRoleAdministrator}, true),
	}
}

func setAccessData(d *schema.ResourceData, values map[string]any) error {
	for k, v := range values {
		if err := d.Set(k, v); err != nil {
			return fmt.Errorf("setting %s: %w", k, err)
		}
	}
	return nil
}

func accessFilterSchema(fields map[string]*schema.Schema) *schema.Schema {
	return &schema.Schema{
		Description: "Optional filters for the returned collection.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: fields,
		},
	}
}

func accessFilter(d *schema.ResourceData) map[string]any {
	filters := d.Get("filter").([]any)
	if len(filters) == 0 || filters[0] == nil {
		return map[string]any{}
	}
	return filters[0].(map[string]any)
}

func listGroupMembers(ctx context.Context, client *myrasec.API, groupID int) ([]myrasec.User, error) {
	return listAccessPages(ctx, map[string]string{"includeRoles": "true"}, func(ctx context.Context, params map[string]string) ([]myrasec.User, error) {
		return client.ListUsersFromGroupContext(ctx, groupID, params)
	}, func(u myrasec.User) int { return u.ID })
}

func memberRole(user myrasec.User, groupID int) (*myrasec.UserRole, error) {
	var found *myrasec.UserRole
	for _, role := range user.Roles {
		if role.GroupID != groupID {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("user %d has multiple role assignments in group %d; resolve them before managing this membership", user.ID, groupID)
		}
		found = &role
	}
	if found == nil {
		return nil, fmt.Errorf("API returned user %d without a role for group %d", user.ID, groupID)
	}
	return found, nil
}
