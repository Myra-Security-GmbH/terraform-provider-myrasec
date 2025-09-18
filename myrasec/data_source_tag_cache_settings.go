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
func dataSourceMyrasecTagCacheSettings() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecTagCacheSettingsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tag_id": {
							Type:     schema.TypeInt,
							Optional: true,
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
						"tag_id": {
							Type:     schema.TypeInt,
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

// dataSourceMyrasecTagCacheSettingsRead ...
func dataSourceMyrasecTagCacheSettingsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	f := prepareTagCacheSettingFilter(d.Get("filter"))
	if f == nil {
		f = &tagCacheSettingFilter{}
	}

	params := map[string]string{}
	if len(f.path) > 0 {
		params["search"] = f.path
	}

	tags, err := listTags(meta, params)
	if err != nil {
		return err
	}

	settingData := make([]any, 0)
	if f.tagId > 0 {
		settings, diags := createSettingsData(f.tagId, meta, params)
		if diags.HasError() {
			return diags
		}
		settingData = append(settingData, settings...)
	} else {
		for _, tag := range tags {
			settings, diags := createSettingsData(tag.ID, meta, params)
			if diags.HasError() {
				return diags
			}
			settingData = append(settingData, settings...)
		}
	}

	if err := d.Set("settings", settingData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

// createSettingsData
func createSettingsData(tagId int, meta any, params map[string]string) ([]any, diag.Diagnostics) {
	settings, diags := listTagCacheSettings(tagId, meta, params)
	settingData := make([]any, 0)
	if diags.HasError() {
		return settingData, diags
	}

	for _, r := range settings {
		settingData = append(settingData, map[string]any{
			"id":            r.ID,
			"created":       r.Created.Format(time.RFC3339),
			"modified":      r.Modified.Format(time.RFC3339),
			"tag_id":        tagId,
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

	return settingData, nil
}

// prepareTagCacheSettingFilter fetches the panic that can happen in parseTagCacheSettingFilter
func prepareTagCacheSettingFilter(d any) *tagCacheSettingFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareTagCacheSettingFilter", r)
		}
	}()

	return parseTagCacheSettingFilter(d)
}

// parseTagCacheSettingFilter converts the filter data to a tagCacheSettingFilter struct
func parseTagCacheSettingFilter(d any) *tagCacheSettingFilter {
	cfg := d.([]any)
	f := &tagCacheSettingFilter{}

	m := cfg[0].(map[string]any)

	tagId, ok := m["tag_id"]
	if ok {
		f.tagId = tagId.(int)
	}

	path, ok := m["path"]
	if ok {
		f.path = path.(string)
	}

	return f
}

// listTagCacheSettings ...
func listTagCacheSettings(tagId int, meta any, params map[string]string) ([]myrasec.CacheSetting, diag.Diagnostics) {
	var diags diag.Diagnostics
	var settings []myrasec.CacheSetting
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListTagCacheSettings(tagId, params)
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

// tagCacheSettingFilter struct ...
type tagCacheSettingFilter struct {
	tagId int
	path  string
}
