package myrasec

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

func resourceMyrasecUserGroupPermission() *schema.Resource { return resourcePermission("group_id") }
