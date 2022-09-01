package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

//
// resourceMyrasecCacheSetting ...
//
func resourceMyrasecCacheSetting() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecCacheSettingCreate,
		ReadContext:   resourceMyrasecCacheSettingRead,
		UpdateContext: resourceMyrasecCacheSettingUpdate,
		DeleteContext: resourceMyrasecCacheSettingDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecCacheSettingImport,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					name := i.(string)
					if isGeneralDomainName(name) {
						return name
					}
					return strings.ToLower(name)
				},
				Description: "The Subdomain for the cache setting.",
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
				Optional:    true,
				Default:     0,
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

//
// resourceMyrasecCacheSettingCreate ...
//
func resourceMyrasecCacheSettingCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
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

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.CreateCacheSetting(setting, domain.ID, subDomainName)
	if err == nil {
		d.SetId(fmt.Sprintf("%d", resp.ID))
		return resourceMyrasecCacheSettingRead(ctx, d, meta)
	}

	setting, errImport := importExistingCacheSetting(setting, domain.ID, subDomainName, meta)
	if errImport != nil {
		log.Printf("[DEBUG] auto-import failed: %s", errImport)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error creating cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", setting.ID))
	return resourceMyrasecCacheSettingRead(ctx, d, meta)
}

//
// resourceMyrasecCacheSettingRead ...
//
func resourceMyrasecCacheSettingRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("subdomain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[subdomain_name] is not set")),
		})
		return diags
	}

	subDomainName := name.(string)
	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing cache setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	setting, diags := findCacheSetting(settingID, meta, subDomainName)
	if diags.HasError() || setting == nil {
		return diags
	}

	setCacheSettingData(d, setting, subDomainName)

	return diags
}

//
// resourceMyrasecCacheSettingUpdate ...
//
func resourceMyrasecCacheSettingUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing cache setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating cache setting: %v", settingID)

	setting, err := buildCacheSetting(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	setting, err = client.UpdateCacheSetting(setting, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	setCacheSettingData(d, setting, subDomainName)

	return diags
}

//
// resourceMyrasecCacheSettingDelete ...
//
func resourceMyrasecCacheSettingDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing cache setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting cache setting: %v", settingID)

	setting, err := buildCacheSetting(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building cache setting",
			Detail:   formatError(err),
		})
		return diags
	}

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.DeleteCacheSetting(setting, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting cache setting",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

//
// resourceMyrasecCacheSettingImport ...
//
func resourceMyrasecCacheSettingImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	subDomainName, settingID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing cache setting ID: [%s]", err.Error())
	}

	setting, diags := findCacheSetting(settingID, meta, subDomainName)
	if diags.HasError() || setting == nil {
		return nil, fmt.Errorf("unable to find cache setting for subdomain [%s] with ID = [%d]", subDomainName, settingID)
	}

	d.SetId(strconv.Itoa(settingID))
	d.Set("setting_id", setting.ID)
	d.Set("subdomain_name", subDomainName)

	resourceMyrasecCacheSettingRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

//
// buildCacheSetting ...
//
func buildCacheSetting(d *schema.ResourceData, meta interface{}) (*myrasec.CacheSetting, error) {
	setting := &myrasec.CacheSetting{
		Type:        d.Get("type").(string),
		Path:        d.Get("path").(string),
		TTL:         d.Get("ttl").(int),
		NotFoundTTL: d.Get("not_found_ttl").(int),
		Sort:        d.Get("sort").(int),
		Enabled:     d.Get("enabled").(bool),
		Enforce:     d.Get("enforce").(bool),
	}

	if d.Get("setting_id").(int) > 0 {
		setting.ID = d.Get("setting_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			setting.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	setting.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	setting.Modified = modified

	return setting, nil
}

//
// findCacheSetting ...
//
func findCacheSetting(settingID int, meta interface{}, subDomainName string) (*myrasec.CacheSetting, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	page := 1
	pageSize := 250
	params := map[string]string{
		"pageSize": strconv.Itoa(pageSize),
		"page":     strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListCacheSettings(domain.ID, subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading cache settings",
				Detail:   formatError(err),
			})
			return nil, diags
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
		Summary:  "Unable to find cache setting",
		Detail:   fmt.Sprintf("Unable to find cache setting with ID = [%d]", settingID),
	})
	return nil, diags
}

//
// setCacheSettingData ...
//
func setCacheSettingData(d *schema.ResourceData, setting *myrasec.CacheSetting, subDomainName string) {
	d.SetId(strconv.Itoa(setting.ID))
	d.Set("setting_id", setting.ID)
	d.Set("created", setting.Created.Format(time.RFC3339))
	d.Set("modified", setting.Modified.Format(time.RFC3339))
	d.Set("type", setting.Type)
	d.Set("path", setting.Path)
	d.Set("ttl", setting.TTL)
	d.Set("not_found_ttl", setting.NotFoundTTL)
	d.Set("sort", setting.Sort)
	d.Set("enabled", setting.Enabled)
	d.Set("enforce", setting.Enforce)
	d.Set("subdomain_name", subDomainName)
}

//
// importExistingCacheSetting ...
//
func importExistingCacheSetting(setting *myrasec.CacheSetting, domainId int, subDomainName string, meta interface{}) (*myrasec.CacheSetting, error) {
	client := meta.(*myrasec.API)

	params := map[string]string{
		"search": setting.Path,
	}

	settings, err := client.ListCacheSettings(domainId, subDomainName, params)
	if err != nil {
		return nil, err
	}

	if len(settings) <= 0 {
		return nil, fmt.Errorf("unable to find existing cache setting for automatic import")
	}

	for _, s := range settings {
		if s.Path != setting.Path ||
			s.Type != setting.Type {
			continue
		}

		return &s, nil
	}
	return nil, fmt.Errorf("unable to find existing cache setting for automatic import")
}
