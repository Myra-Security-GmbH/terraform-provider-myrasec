package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// resourceMyrasecTagCacheSetting ...
func resourceMyrasecTagCacheSetting() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecTagCacheSettingCreate,
		ReadContext:   resourceMyrasecTagCacheSettingRead,
		UpdateContext: resourceMyrasecTagCacheSettingUpdate,
		DeleteContext: resourceMyrasecTagCacheSettingDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecTagCacheSettingImport,
		},
		Schema: map[string]*schema.Schema{
			"tag_id": {
				Type:        schema.TypeInt,
				Required:    true,
				ForceNew:    true,
				Description: "The Id of the tag for the cache setting.",
			},
			"setting_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the cache setting.",
			},
			"modified": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date of last modification.",
			},
			"created": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date of creation.",
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"exact", "prefix", "suffix"}, false),
				Description:  "Type how path should match.",
			},
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path which must match to cache response.",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "Time to live.",
			},
			"not_found_ttl": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "How long an object will be cached. Origin responses with the HTTP codes 404 will be cached.",
			},
			"sort": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "The order in which the cache rules take action as long as the cache sorting is activated.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Define wether this cache setting is enabled or not.",
			},
			"enforce": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enforce cache TTL allows you to set the cache TTL (Cache Control: max-age) in the backend regardless of the response sent from your Origin.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecTagCacheSettingCreate ...
func resourceMyrasecTagCacheSettingCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	setting, err := buildCacheSetting(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	resp, err := client.CreateTagCacheSetting(setting, tagID.(int))
	if err == nil {
		d.SetId(fmt.Sprintf("%d", resp.ID))
		return resourceMyrasecTagCacheSettingRead(ctx, d, meta)
	}

	setting, errImport := importExistingTagCacheSetting(setting, tagID.(int), meta)
	if errImport != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error creating tag cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", setting.ID))
	return resourceMyrasecTagCacheSettingRead(ctx, d, meta)
}

// resourceMyrasecTagCacheSettingRead ...
func resourceMyrasecTagCacheSettingRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing tag cache setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	setting, diags := findTagCacheSetting(settingID, tagID.(int), meta)
	if diags.HasError() || setting == nil {
		return diags
	}

	setTagCacheSettingData(d, setting, tagID.(int))

	return diags
}

// resourceMyrasecTagCacheSettingUpdate ...
func resourceMyrasecTagCacheSettingUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing tag cache setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating tag cache setting: %v", settingID)
	setting, err := buildCacheSetting(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	setting, err = client.UpdateTagCacheSetting(setting, tagID.(int))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating tag cache setting",
			Detail:   formatError(err),
		})
	}

	setTagCacheSettingData(d, setting, tagID.(int))

	return diags
}

// resourceMyrasecTagCacheSettingDelete ...
func resourceMyrasecTagCacheSettingDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	setting, err := buildCacheSetting(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	_, err = client.DeleteTagCacheSetting(setting, tagID.(int))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting tag cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	return diags
}

// resourceMyrasecTagCacheSettingImport ...
func resourceMyrasecTagCacheSettingImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	tag, settingID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing tag cache setting ID: [%s]", err.Error())
	}

	log.Printf("Importing tag cache setting with ID [%d] and tagID [%v]", settingID, tag)

	tagID, err := strconv.Atoi(tag)
	if err != nil {
		return nil, fmt.Errorf("unable to convert tagID to int")
	}

	d.SetId(strconv.Itoa(settingID))
	d.Set("tag_id", tagID)
	resourceMyrasecTagCacheSettingRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// findTagCacheSetting
func findTagCacheSetting(settingID int, tagID int, meta interface{}) (*myrasec.CacheSetting, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	pageSize := 250
	params := map[string]string{
		"pageSize": strconv.Itoa(pageSize),
		"page":     strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)

		res, err := client.ListTagCacheSettings(tagID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading tag cache settings",
				Detail:   formatError(err),
			})
		}

		for _, s := range res {
			if s.ID == settingID {
				return &s, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find tag cache setting",
		Detail:   fmt.Sprintf("Unable to find tag cache setting with ID = [%d]", settingID),
	})

	return nil, diags
}

// setTagCacheSettingData
func setTagCacheSettingData(d *schema.ResourceData, setting *myrasec.CacheSetting, tagID int) {
	d.SetId(strconv.Itoa(setting.ID))
	d.Set("setting_id", setting.ID)
	d.Set("tag_id", tagID)
	d.Set("created", setting.Created.Format(time.RFC3339))
	d.Set("modified", setting.Modified.Format(time.RFC3339))
	d.Set("enabled", setting.Enabled)
	d.Set("enforce", setting.Enforce)
	d.Set("not_found_ttl", setting.NotFoundTTL)
	d.Set("path", setting.Path)
	d.Set("sort", setting.Sort)
	d.Set("ttl", setting.TTL)
	d.Set("type", setting.Type)
}

// importExistingTagCacheSetting
func importExistingTagCacheSetting(setting *myrasec.CacheSetting, tagID int, meta interface{}) (*myrasec.CacheSetting, error) {
	client := meta.(*myrasec.API)

	params := map[string]string{
		"search": setting.Path,
	}

	settings, err := client.ListTagCacheSettings(tagID, params)
	if err != nil {
		return nil, err
	}

	if len(settings) <= 0 {
		return nil, fmt.Errorf("unable to find existing tag cache setting for automatic import")
	}

	for _, s := range settings {
		if s.Path != setting.Path || s.Type != setting.Type {
			continue
		}
		return &s, nil
	}

	return nil, fmt.Errorf("unable to find existing cache setting for automatic import")
}
