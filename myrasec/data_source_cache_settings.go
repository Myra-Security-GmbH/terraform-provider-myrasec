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

// dataSourceMyrasecCacheSettings ...
func dataSourceMyrasecCacheSettings() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecCacheSettingsRead,
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
						"path": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"settings": {
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
						"path": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ttl": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"not_found_ttl": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"sort": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"enforce": {
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

// dataSourceMyrasecCacheSettingsRead ...
func dataSourceMyrasecCacheSettingsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareCacheSettingFilter(d.Get("filter"))
	if f == nil {
		f = &cacheSettingFilter{}
	}

	params := map[string]string{}
	if len(f.path) > 0 {
		params["search"] = f.path
	}

	settings, diags := listCacheSettings(meta, f.subDomainName, params)
	if diags.HasError() {
		return diags
	}

	settingData := make([]interface{}, 0)
	for _, r := range settings {
		settingData = append(settingData, map[string]interface{}{
			"id":            r.ID,
			"created":       r.Created.Format(time.RFC3339),
			"modified":      r.Modified.Format(time.RFC3339),
			"type":          r.Type,
			"path":          r.Path,
			"ttl":           r.TTL,
			"not_found_ttl": r.NotFoundTTL,
			"sort":          r.Sort,
			"enabled":       r.Enabled,
			"enforce":       r.Enforce,
			"comment":       r.Comment,
		})
	}

	if err := d.Set("settings", settingData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil

}

// prepareCacheSettingFilter fetches the panic that can happen in parseCacheSettingFilter
func prepareCacheSettingFilter(d interface{}) *cacheSettingFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareCacheSettingFilter", r)
		}
	}()

	return parseCacheSettingFilter(d)
}

// parseCacheSettingFilter converts the filter data to a cacheSettingFilter struct
func parseCacheSettingFilter(d interface{}) *cacheSettingFilter {
	cfg := d.([]interface{})
	f := &cacheSettingFilter{}

	m := cfg[0].(map[string]interface{})

	subDomainName, ok := m["subdomain_name"]
	if ok {
		f.subDomainName = subDomainName.(string)
	}

	path, ok := m["path"]
	if ok {
		f.path = path.(string)
	}

	return f
}

// listCacheSettings ...
func listCacheSettings(meta interface{}, subDomainName string, params map[string]string) ([]myrasec.CacheSetting, diag.Diagnostics) {
	var diags diag.Diagnostics
	var settings []myrasec.CacheSetting
	pageSize := 250

	client := meta.(*myrasec.API)

	domain, err := client.FetchDomainForSubdomainName(subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return settings, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListCacheSettings(domain.ID, subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching cache settings",
				Detail:   formatError(err),
			})
			return settings, diags
		}
		settings = append(settings, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return settings, diags
}

// cacheSettingFilter struct ...
type cacheSettingFilter struct {
	subDomainName string
	path          string
}
