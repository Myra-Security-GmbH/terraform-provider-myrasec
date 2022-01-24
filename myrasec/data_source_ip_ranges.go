package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceMyrasecIPRanges ...
//
func dataSourceMyrasecIPRanges() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecIPRangesRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"search": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"type": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"ipranges": {
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
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"valid_from": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"valid_to": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"network": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"comment": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// dataSourceMyrasecIPRangesRead ...
//
func dataSourceMyrasecIPRangesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	f := prepareIPRangeFilter(d.Get("filter"))
	if f == nil {
		f = &ipRangeFilter{}
	}

	params := map[string]string{}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	filters, err := client.ListIPRanges(params)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching ip ranges",
			Detail:   err.Error(),
		})
		return diags
	}

	ipRangeData := make([]interface{}, 0)
	for _, r := range filters {
		data := map[string]interface{}{
			"id":       r.ID,
			"created":  r.Created.Format(time.RFC3339),
			"modified": r.Modified.Format(time.RFC3339),
			"network":  r.Network,
			"enabled":  r.Enabled,
			"comment":  r.Comment,
		}

		if r.ValidFrom != nil {
			data["valid_from"] = r.ValidFrom.Format(time.RFC3339)
		}

		if r.ValidTo != nil {
			data["valid_to"] = r.ValidTo.Format(time.RFC3339)
		}

		ipRangeData = append(ipRangeData, data)
	}

	if err := d.Set("ipranges", ipRangeData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags

}

//
// prepareIPRangeFilter fetches the panic that can happen in parseIPRangeFilter
//
func prepareIPRangeFilter(d interface{}) *ipRangeFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareIPRangeFilter", r)
		}
	}()

	return parseIPRangeFilter(d)
}

//
// parseRateLimitFilter converts the filter data to a rateLimitFilter struct
//
func parseIPRangeFilter(d interface{}) *ipRangeFilter {
	cfg := d.([]interface{})
	f := &ipRangeFilter{}

	m := cfg[0].(map[string]interface{})

	ipVersionType, ok := m["type"]
	if ok {
		f.ipVersionType = ipVersionType.(string)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	return f
}

//
// ipRangeFilter struct ...
//
type ipRangeFilter struct {
	search        string
	ipVersionType string
}
