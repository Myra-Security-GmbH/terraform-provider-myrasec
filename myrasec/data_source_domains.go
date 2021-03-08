package myrasec

import (
	"fmt"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceMyrasecDomains ...
//
func dataSourceMyrasecDomains() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceMyrasecDomainsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"domains": {
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
						"auto_update": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"paused": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"paused_until": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

//
// dataSourceMyrasecDomainsRead ...
//
func dataSourceMyrasecDomainsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	f := parseDomainFilter(d.Get("filter"))

	params := map[string]string{}
	if len(f.name) > 0 {
		params["search"] = f.name
	}

	domains, err := client.ListDomains(params)
	if err != nil {
		return fmt.Errorf("Error fetching domains: %s", err)
	}

	domainData := make([]interface{}, 0)
	for _, r := range domains {
		if f.id != 0 && r.ID != f.id {
			continue
		}

		domainData = append(domainData, map[string]interface{}{
			"id":           r.ID,
			"created":      r.Created.Format(time.RFC3339),
			"modified":     r.Modified.Format(time.RFC3339),
			"name":         r.Name,
			"auto_update":  r.AutoUpdate,
			"paused":       r.Paused,
			"paused_until": r.PausedUntil,
		})
	}

	if err := d.Set("domains", domainData); err != nil {
		return err
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

//
// parseDomainFilter converts the filter data to a domainFilter struct
//
func parseDomainFilter(d interface{}) *domainFilter {
	cfg := d.([]interface{})
	f := &domainFilter{}

	m := cfg[0].(map[string]interface{})
	name, ok := m["name"]
	if ok {
		f.name = name.(string)
	}

	id, ok := m["id"]
	if ok {
		f.id = id.(int)
	}

	return f
}

//
// domainFilter struct ...
//
type domainFilter struct {
	id   int
	name string
}
