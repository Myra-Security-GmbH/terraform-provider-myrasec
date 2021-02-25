package myrasec

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/Myra-Security-GmbH/myrasec-go/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

//
// resourceMyrasecIPFilter ...
//
func resourceMyrasecIPFilter() *schema.Resource {
	return &schema.Resource{
		Create: resourceMyrasecIPFilterCreate,
		Read:   resourceMyrasecIPFilterRead,
		Delete: resourceMyrasecIPFilterDelete,

		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the ip filter.",
			},
			"filter_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the IP filter.",
			},
			"modified": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date of last modification.",
			},
			"created": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date of creation.",
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToUpper(i.(string))
				},
				ValidateFunc: validation.StringInSlice([]string{"BLACKLIST", "WHITELIST", "WHITELIST_REQUEST_LIMITER"}, false),
				Description:  "Type of the IP filter.",
			},
			"value": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The IP you want to whitelist or blacklist. By using CIDR notation on IPv4 IPs, you are able to define whole subnets.",
			},
			"expire_date": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Expire date schedules the deaktivation of the filter. If none is set, the filter will be active until manual deactivation.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Enable or disable a filter.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecIPFilterCreate ...
//
func resourceMyrasecIPFilterCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		return fmt.Errorf("Error building ip filter: %s", err)
	}

	resp, err := client.CreateIPFilter(filter, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error creating filter: %s", err)
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecIPFilterRead(d, meta)
}

//
// resourceMyrasecIPFilterRead ...
//
func resourceMyrasecIPFilterRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	filterID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing filter id: %s", err)
	}

	filters, err := client.ListIPFilters(d.Get("subdomain_name").(string), nil)
	if err != nil {
		return fmt.Errorf("Error fetching filters: %s", err)
	}

	for _, r := range filters {
		if r.ID != filterID {
			continue
		}
		d.Set("filter_id", r.ID)
		d.Set("created", r.Created.Format(time.RFC3339))
		d.Set("modified", r.Modified.Format(time.RFC3339))
		d.Set("type", r.Type)
		d.Set("value", r.Value)
		d.Set("enabled", r.Enabled)
		if r.ExpireDate != nil {
			d.Set("expire_date", r.ExpireDate.Format(time.RFC3339))
		}
		break
	}

	return nil
}

//
// resourceMyrasecIPFilterDelete ...
//
func resourceMyrasecIPFilterDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	filterID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing filter id: %s", err)
	}

	log.Printf("[INFO] Deleting ip filter: %v", filterID)

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		return fmt.Errorf("Error building ip filter: %s", err)
	}

	_, err = client.DeleteIPFilter(filter, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error deleting ip filter: %s", err)
	}
	return err
}

//
// buildIPFilter ...
//
func buildIPFilter(d *schema.ResourceData, meta interface{}) (*myrasec.IPFilter, error) {
	filter := &myrasec.IPFilter{
		Type:    d.Get("type").(string),
		Value:   d.Get("value").(string),
		Enabled: d.Get("enabled").(bool),
	}

	if d.Get("filter_id").(int) > 0 {
		filter.ID = d.Get("filter_id").(int)
	}

	if len(d.Get("created").(string)) > 0 {
		created, err := time.Parse(time.RFC3339, d.Get("created").(string))
		if err != nil {
			return nil, err
		}

		filter.Created = &types.DateTime{
			Time: created,
		}
	}

	if len(d.Get("modified").(string)) > 0 {
		modified, err := time.Parse(time.RFC3339, d.Get("modified").(string))
		if err != nil {
			return nil, err
		}
		filter.Modified = &types.DateTime{
			Time: modified,
		}
	}

	if len(d.Get("expire_date").(string)) > 0 {
		expireDate, err := time.Parse(time.RFC3339, d.Get("expire_date").(string))
		if err != nil {
			return nil, err
		}
		filter.ExpireDate = &types.DateTime{
			Time: expireDate,
		}
	}

	return filter, nil
}
