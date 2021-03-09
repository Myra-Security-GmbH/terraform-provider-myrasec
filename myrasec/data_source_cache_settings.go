package myrasec

import (
	"fmt"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceMyrasecCacheSettings ...
//
func dataSourceMyrasecCacheSettings() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceMyrasecCacheSettingsRead,
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
					},
				},
			},
		},
	}
}

//
// dataSourceMyrasecCacheSettingsRead ...
//
func dataSourceMyrasecCacheSettingsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	f := prepareCacheSettingFilter(d.Get("filter"))
	if f == nil {
		f = &cacheSettingFilter{}
	}

	params := map[string]string{}
	if len(f.path) > 0 {
		params["search"] = f.path
	}

	settings, err := client.ListCacheSettings(f.subDomainName, params)
	if err != nil {
		return fmt.Errorf("Error fetching cache settings: %s", err)
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
		})
	}

	if err := d.Set("settings", settingData); err != nil {
		return err
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil

}

//
// prepareCacheSettingFilter ...
//
func prepareCacheSettingFilter(d interface{}) *cacheSettingFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareCacheSettingFilter", r)
		}
	}()

	return parseCacheSettingFilter(d)
}

//
// parseCacheSettingFilter converts the filter data to a cacheSettingFilter struct
//
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

//
// cacheSettingFilter struct ...
//
type cacheSettingFilter struct {
	subDomainName string
	path          string
}
