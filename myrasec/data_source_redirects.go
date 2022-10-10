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

// dataSourceMyrasecRedirects ...
func dataSourceMyrasecRedirects() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecRedirectsRead,
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
						"comment": {
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
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// dataSourceMyrasecRedirectsRead ...
func dataSourceMyrasecRedirectsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareRedirectFilter(d.Get("filter"))
	if f == nil {
		f = &redirectFilter{}
	}

	params := map[string]string{}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	redirects, diags := listRedirects(meta, f.subDomainName, params)
	if diags.HasError() {
		return diags
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
			"comment":        r.Comment,
		})
	}

	if err := d.Set("redirects", redirectData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

// prepareRedirectFilter fetches the panic that can happen in parseRedirectFilter
func prepareRedirectFilter(d interface{}) *redirectFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareRedirectFilter", r)
		}
	}()

	return parseRedirectFilter(d)
}

// parseRedirectFilter converts the filter data to a redirectFilter struct
func parseRedirectFilter(d interface{}) *redirectFilter {
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

// listRedirects ...
func listRedirects(meta interface{}, subDomainName string, params map[string]string) ([]myrasec.Redirect, diag.Diagnostics) {
	var diags diag.Diagnostics
	var redirects []myrasec.Redirect
	pageSize := 250

	client := meta.(*myrasec.API)

	domain, err := client.FetchDomainForSubdomainName(subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return redirects, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListRedirects(domain.ID, subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching rate limits",
				Detail:   formatError(err),
			})
			return redirects, diags
		}
		redirects = append(redirects, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return redirects, diags
}

// redirectFilter struct ...
type redirectFilter struct {
	subDomainName string
	search        string
}
