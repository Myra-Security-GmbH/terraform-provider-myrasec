package myrasec

import (
	"fmt"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceWAFActions ...
//
func dataSourceWAFActions() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWAFActionsRead,
		Schema: map[string]*schema.Schema{
			"waf_actions": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"modified": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"custom_key": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"available_phases": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"force_custom_values": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

//
// dataSourceWAFActionsRead ...
//
func dataSourceWAFActionsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	actions, err := client.ListWAFActions()
	if err != nil {
		return fmt.Errorf("Error fetching WAF actions: %s", err)
	}

	if err := d.Set("waf_actions", actions); err != nil {
		return err
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}
