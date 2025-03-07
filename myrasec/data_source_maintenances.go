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

// dataSourceMyrasecMaintenances ...
func dataSourceMyrasecMaintenances() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecMaintenancesRead,
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
					},
				},
			},
			"maintenances": {
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
						"start": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"end": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"active": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"content_hash": {
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

// dataSourceMyrasecMaintenancesRead
func dataSourceMyrasecMaintenancesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareMaintenanceFilter(d.Get("filter"))

	if f == nil {
		f = &maintenanceFilter{}
	}
	params := map[string]string{}

	maintenances, diags := listMaintenances(meta, f.subDomainName, params)
	if diags.HasError() {
		return diags
	}

	maintenanceData := make([]interface{}, 0)

	for _, mp := range maintenances {
		var created string
		if mp.Created != nil {
			created = mp.Created.Format(time.RFC3339)
		}

		var modified string
		if mp.Modified != nil {
			modified = mp.Modified.Format(time.RFC3339)
		}

		data := map[string]interface{}{
			"id":             mp.ID,
			"created":        created,
			"modified":       modified,
			"start":          mp.Start.Format(time.RFC3339),
			"end":            mp.End.Format(time.RFC3339),
			"active":         mp.Active,
			"content_hash":   createContentHash(mp.Content),
			"subdomain_name": mp.FQDN,
		}
		maintenanceData = append(maintenanceData, data)
	}

	if err := d.Set("maintenances", maintenanceData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

// prepareMaintenanceFilter
func prepareMaintenanceFilter(d interface{}) *maintenanceFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareMaintenanceFilter", r)
		}
	}()

	return parseMaintenanceFilter(d)
}

// parseMaintenanceFilter
func parseMaintenanceFilter(d interface{}) *maintenanceFilter {
	cfg := d.([]interface{})
	f := &maintenanceFilter{}

	m := cfg[0].(map[string]interface{})

	subDomainName, ok := m["subdomain_name"]
	if ok {
		f.subDomainName = subDomainName.(string)
	}

	return f
}

// listMaintenances ...
func listMaintenances(meta interface{}, subdomainName string, params map[string]string) ([]myrasec.Maintenance, diag.Diagnostics) {
	var diags diag.Diagnostics
	var maintenances []myrasec.Maintenance
	pageSize := 100

	client := meta.(*myrasec.API)
	domain, err := client.FetchDomain(subdomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   formatError(err),
		})
		return maintenances, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListMaintenances(domain.ID, subdomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching maintenances",
				Detail:   formatError(err),
			})
			return maintenances, diags
		}
		maintenances = append(maintenances, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return maintenances, diags
}

// maintenanceFilter
type maintenanceFilter struct {
	subDomainName string
}
