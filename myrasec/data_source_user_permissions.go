package myrasec

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

func dataSourceMyrasecUserPermissions() *schema.Resource { return dataSourcePermissions("user_id") }
