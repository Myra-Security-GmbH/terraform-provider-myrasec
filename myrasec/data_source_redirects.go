package myrasec

import (
	"fmt"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceRedirects ...
//
func dataSourceRedirects() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceRedirectsRead,
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
			"redirects": {
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
						"matching_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"subdomain_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"source": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"destination": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"sort": {
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
// dataSourceRedirectsRead ...
//
func dataSourceRedirectsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	f := parseRedirectsFilter(d.Get("filter"))

	params := map[string]string{}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	redirects, err := client.ListRedirects(f.subDomainName, params)
	if err != nil {
		return fmt.Errorf("Error fetching redirects: %s", err)
	}

	redirectData := make([]interface{}, 0)
	for _, r := range redirects {
		redirectData = append(redirectData, map[string]interface{}{
			"id":             r.ID,
			"created":        r.Created.Format(time.RFC3339),
			"modified":       r.Modified.Format(time.RFC3339),
			"type":           r.Type,
			"sort":           r.Sort,
			"enabled":        r.Enabled,
			"matching_type":  r.MatchingType,
			"subdomain_name": r.SubDomainName,
			"source":         r.Source,
			"destination":    r.Destination,
		})
	}

	if err := d.Set("redirects", redirectData); err != nil {
		return err
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil

}

//
// parseRedirectsFilter converts the filter data to a redirectFilter struct
//
func parseRedirectsFilter(d interface{}) *redirectFilter {
	cfg := d.([]interface{})
	f := &redirectFilter{}

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
// redirectFilter struct ...
//
type redirectFilter struct {
	subDomainName string
	search        string
}
