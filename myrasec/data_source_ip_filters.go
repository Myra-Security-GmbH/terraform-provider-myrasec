package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceMyrasecIPFilters ...
//
func dataSourceMyrasecIPFilters() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecIPFiltersRead,
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
						"type": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"ipfilters": {
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
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"expire_date": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
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
// dataSourceMyrasecIPFiltersRead ...
//
func dataSourceMyrasecIPFiltersRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareIPFilterFilter(d.Get("filter"))
	if f == nil {
		f = &ipFilterFilter{}
	}

	params := map[string]string{}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	if len(f.filterType) > 0 {
		params["type"] = f.filterType
	}

	filters, diags := listIPFilters(meta, f.subDomainName, params)
	if diags.HasError() {
		return diags
	}

	ipFilterData := make([]interface{}, 0)
	for _, r := range filters {
		data := map[string]interface{}{
			"id":       r.ID,
			"created":  r.Created.Format(time.RFC3339),
			"modified": r.Modified.Format(time.RFC3339),
			"type":     r.Type,
			"value":    r.Value,
			"enabled":  r.Enabled,
			"comment":  r.Comment,
		}

		if r.ExpireDate != nil {
			data["expire_date"] = r.ExpireDate.Format(time.RFC3339)
		}

		ipFilterData = append(ipFilterData, data)
	}

	if err := d.Set("ipfilters", ipFilterData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags

}

//
// prepareIPFilterFilter fetches the panic that can happen in parseIPFilterFilter
//
func prepareIPFilterFilter(d interface{}) *ipFilterFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareIPFilterFilter", r)
		}
	}()

	return parseIPFilterFilter(d)
}

//
// parseRateLimitFilter converts the filter data to a rateLimitFilter struct
//
func parseIPFilterFilter(d interface{}) *ipFilterFilter {
	cfg := d.([]interface{})
	f := &ipFilterFilter{}

	m := cfg[0].(map[string]interface{})

	subDomainName, ok := m["subdomain_name"]
	if ok {
		f.subDomainName = subDomainName.(string)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	filterType, ok := m["type"]
	if ok {
		f.filterType = filterType.(string)
	}

	return f
}

//
// listIPFilters ...
//
func listIPFilters(meta interface{}, subDomainName string, params map[string]string) ([]myrasec.IPFilter, diag.Diagnostics) {
	var diags diag.Diagnostics
	var filters []myrasec.IPFilter
	pageSize := 250

	client := meta.(*myrasec.API)

	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return filters, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListIPFilters(domain.ID, subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching IP filters",
				Detail:   formatError(err),
			})
			return filters, diags
		}
		filters = append(filters, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return filters, diags
}

//
// ipFilterFilter struct ...
//
type ipFilterFilter struct {
	subDomainName string
	search        string
	filterType    string
}
