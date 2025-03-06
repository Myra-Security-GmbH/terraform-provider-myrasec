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

// dataSourceMyrasecMaintenanceTemplates ...
func dataSourceMyrasecMaintenanceTemplates() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecMaintenanceTemplatesRead,
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
			"maintenance_templates": {
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
							Required: true,
						},
						"content_hash": {
							Type:     schema.TypeString,
							Required: true,
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

// dataSourceMyrasecMaintenanceTemplatesRead ...
func dataSourceMyrasecMaintenanceTemplatesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareMaintenanceTemplateFilter(d.Get("filter"))

	if f == nil {
		f = &maintenanceTemplateFilter{}
	}
	params := map[string]string{}

	templates, diags := listMaintenanceTemplates(meta, f.domainName, params)
	if diags.HasError() {
		return diags
	}

	maintenanceTemplateData := make([]interface{}, 0)

	for _, mt := range templates {
		var created string
		if mt.Created != nil {
			created = mt.Created.Format(time.RFC3339)
		}

		var modified string
		if mt.Modified != nil {
			modified = mt.Modified.Format(time.RFC3339)
		}

		data := map[string]interface{}{
			"id":           mt.ID,
			"created":      created,
			"modified":     modified,
			"name":         mt.Name,
			"content_hash": createContentHash(mt.Content),
		}
		maintenanceTemplateData = append(maintenanceTemplateData, data)
	}

	if err := d.Set("maintenance_templates", maintenanceTemplateData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

// listMaintenanceTemplates ...
func listMaintenanceTemplates(meta interface{}, domainName string, params map[string]string) ([]myrasec.MaintenanceTemplate, diag.Diagnostics) {
	var diags diag.Diagnostics
	var templates []myrasec.MaintenanceTemplate
	pageSize := 100

	client := meta.(*myrasec.API)
	domain, err := client.FetchDomain(domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   formatError(err),
		})
		return templates, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListMaintenanceTemplates(domain.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching maintenance templates",
				Detail:   formatError(err),
			})
			return templates, diags
		}
		templates = append(templates, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return templates, diags
}

// prepareMaintenanceTemplateFilter ...
func prepareMaintenanceTemplateFilter(d interface{}) *maintenanceTemplateFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareMaintenanceTemplateFilter", r)
		}
	}()

	return parseMaintenanceTemplateFilter(d)
}

// parseMaintenanceTemplateFilter ...
func parseMaintenanceTemplateFilter(d interface{}) *maintenanceTemplateFilter {
	cfg := d.([]interface{})
	f := &maintenanceTemplateFilter{}

	m := cfg[0].(map[string]interface{})

	domainName, ok := m["domain_name"]
	if ok {
		f.domainName = domainName.(string)
	}

	return f
}

// maintenanceTemplateFilter ...
type maintenanceTemplateFilter struct {
	domainName string
}
