package myrasec

import (
	"fmt"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceWAFConditions ...
//
func dataSourceWAFConditions() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWAFConditionsRead,
		Schema: map[string]*schema.Schema{
			"waf_conditions": {
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
						"matching_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"alias": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"key": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"category": {
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
// dataSourceWAFConditionsRead ...
//
func dataSourceWAFConditionsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	conditions, err := client.ListWAFConditions()
	if err != nil {
		return fmt.Errorf("Error fetching WAF conditions: %s", err)
	}

	if err := d.Set("waf_conditions", conditions); err != nil {
		return err
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}
