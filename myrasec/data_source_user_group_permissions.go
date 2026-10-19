package myrasec

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

func dataSourceMyrasecUserGroupPermissions() *schema.Resource {
	return dataSourcePermissions("group_id")
}
