package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceMyrasecErrorPages
//
func dataSourceMyrasecErrorPages() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecErrorPageRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain_name": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"error_pages": {
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
						"error_code": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"content": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"subdomain_name": {
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
// dataSourceMyrasecErrorPageRead
//
func dataSourceMyrasecErrorPageRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareErrorPageFilter(d.Get("filter"))
	if f == nil {
		f = &errorPageFilter{}
	}

	params := map[string]string{}

	errorPages, diags := listErrorPages(meta, f.domainName, params)
	if diags.HasError() {
		return diags
	}

	errorPageData := make([]interface{}, 0)

	for _, ep := range errorPages {

		var created string
		if ep.Created != nil {
			created = ep.Created.Format(time.RFC3339)
		}

		var modified string
		if ep.Modified != nil {
			modified = ep.Modified.Format(time.RFC3339)
		}

		data := map[string]interface{}{
			"id":             ep.ID,
			"created":        created,
			"modified":       modified,
			"error_code":     ep.ErrorCode,
			"content":        ep.Content,
			"subdomain_name": ep.SubDomainName,
		}

		errorPageData = append(errorPageData, data)
	}
	if err := d.Set("error_pages", errorPageData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

//
// prepareErrorPageFilter fetches the panic that can happen in parseErrorPageFilter
//
func prepareErrorPageFilter(d interface{}) *errorPageFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareErrorPageFilter", r)
		}
	}()

	return parseErrorPageFilter(d)
}

//
// parseErrorPageFilter converts the filter data to a errorPageFilter struct
//
func parseErrorPageFilter(d interface{}) *errorPageFilter {
	cfg := d.([]interface{})
	f := &errorPageFilter{}

	m := cfg[0].(map[string]interface{})

	domainName, ok := m["domain_name"]
	if ok {
		f.domainName = domainName.(string)
	}

	return f
}

//
// listErrorPages
//
func listErrorPages(meta interface{}, domainName string, params map[string]string) ([]myrasec.ErrorPage, diag.Diagnostics) {
	var diags diag.Diagnostics
	var errorPages []myrasec.ErrorPage
	pageSize := 250

	client := meta.(*myrasec.API)
	domain, err := fetchDomain(client, domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   err.Error(),
		})
		return errorPages, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListErrorPages(domain.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching error pages",
				Detail:   err.Error(),
			})
			return errorPages, diags
		}
		errorPages = append(errorPages, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return errorPages, diags
}

//
// errorPageFilter
//
type errorPageFilter struct {
	domainName string
}
