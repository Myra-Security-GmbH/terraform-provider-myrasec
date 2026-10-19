package myrasec

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

func resourceMyrasecUserPermission() *schema.Resource { return resourcePermission("user_id") }
