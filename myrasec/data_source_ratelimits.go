package myrasec

import (
	"fmt"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceRateLimits ...
//
func dataSourceRateLimits() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceRateLimitsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"subdomain_name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"search": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"ratelimits": {
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
						"subdomain_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"network": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"burst": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"timeframe": {
							Type:     schema.TypeInt,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

//
// dataSourceRateLimitsRead ...
//
func dataSourceRateLimitsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	f := parseRedirectsFilter(d.Get("filter"))

	params := map[string]string{
		"subDomainName": f.subDomainName,
	}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	redirects, err := client.ListRateLimits("dns", params)
	if err != nil {
		return fmt.Errorf("Error fetching rate limits: %s", err)
	}

	rateLimitData := make([]interface{}, 0)
	for _, r := range redirects {
		rateLimitData = append(rateLimitData, map[string]interface{}{
			"id":             r.ID,
			"created":        r.Created.Format(time.RFC3339),
			"modified":       r.Modified.Format(time.RFC3339),
			"subdomain_name": r.SubDomainName,
			"type":           r.Type,
			"network":        r.Network,
			"value":          r.Value,
			"burst":          r.Burst,
			"timeframe":      r.Timeframe,
		})
	}

	if err := d.Set("ratelimits", rateLimitData); err != nil {
		return err
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil

}

//
// parseRateLimitFilter converts the filter data to a rateLimitFilter struct
//
func parseRateLimitFilter(d interface{}) *rateLimitFilter {
	cfg := d.([]interface{})
	f := &rateLimitFilter{}

	m := cfg[0].(map[string]interface{})

	subDomainName, ok := m["subdomain_name"]
	if ok {
		f.subDomainName = subDomainName.(string)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	return f
}

//
// rateLimitFilter struct ...
//
type rateLimitFilter struct {
	subDomainName string
	search        string
}
