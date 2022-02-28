package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/Myra-Security-GmbH/myrasec-go/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

//
// resourceMyrasecIPFilter ...
//
func resourceMyrasecIPFilter() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecIPFilterCreate,
		ReadContext:   resourceMyrasecIPFilterRead,
		UpdateContext: resourceMyrasecIPFilterUpdate,
		DeleteContext: resourceMyrasecIPFilterDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the ip filter.",
			},
			"filter_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the IP filter.",
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
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToUpper(i.(string))
				},
				ValidateFunc: validation.StringInSlice([]string{"BLACKLIST", "WHITELIST", "WHITELIST_REQUEST_LIMITER"}, false),
				Description:  "Type of the IP filter.",
			},
			"value": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The IP you want to whitelist or blacklist. By using CIDR notation on IPv4 IPs, you are able to define whole subnets.",
			},
			"expire_date": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Expire date schedules the deaktivation of the filter. If none is set, the filter will be active until manual deactivation.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable or disable a filter.",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "A comment to describe this IP filter.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecIPFilterCreate ...
//
func resourceMyrasecIPFilterCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building IP filter",
			Detail:   err.Error(),
		})
		return diags
	}

	resp, err := client.CreateIPFilter(filter, d.Get("subdomain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating IP filter",
			Detail:   err.Error(),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecIPFilterRead(ctx, d, meta)
}

//
// resourceMyrasecIPFilterRead ...
//
func resourceMyrasecIPFilterRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	var subDomainName string
	var filterID int
	var err error

	name, ok := d.GetOk("subdomain_name")
	if ok && !strings.Contains(d.Id(), ":") {
		subDomainName = name.(string)
		filterID, err = strconv.Atoi(d.Id())
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error parsing IP filter ID",
				Detail:   err.Error(),
			})
			return diags
		}

	} else {
		subDomainName, filterID, err = parseResourceServiceID(d.Id())
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error parsing IP filter ID",
				Detail:   err.Error(),
			})
			return diags
		}
	}

	filter, diags := findIPFilter(filterID, meta, subDomainName, nil)
	if diags.HasError() {
		return diags
	}

	if filter == nil {
		return diags
	}

	d.SetId(strconv.Itoa(filterID))
	d.Set("filter_id", filter.ID)
	d.Set("created", filter.Created.Format(time.RFC3339))
	d.Set("modified", filter.Modified.Format(time.RFC3339))
	d.Set("type", filter.Type)
	d.Set("value", filter.Value)
	d.Set("enabled", filter.Enabled)
	d.Set("comment", filter.Comment)
	d.Set("subdomain_name", subDomainName)

	if filter.ExpireDate != nil {
		d.Set("expire_date", filter.ExpireDate.Format(time.RFC3339))
	}

	return diags
}

//
// resourceMyrasecIPFilterUpdate ...
//
func resourceMyrasecIPFilterUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	filterID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing IP filter ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Updating IP filter: %v", filterID)

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building IP filter",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.UpdateIPFilter(filter, d.Get("subdomain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating IP filter",
			Detail:   err.Error(),
		})
		return diags
	}

	return resourceMyrasecIPFilterRead(ctx, d, meta)
}

//
// resourceMyrasecIPFilterDelete ...
//
func resourceMyrasecIPFilterDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	filterID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing IP filter ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Deleting IP filter: %v", filterID)

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building IP filter",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.DeleteIPFilter(filter, d.Get("subdomain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting IP filter",
			Detail:   err.Error(),
		})
		return diags
	}
	return diags
}

//
// buildIPFilter ...
//
func buildIPFilter(d *schema.ResourceData, meta interface{}) (*myrasec.IPFilter, error) {
	filter := &myrasec.IPFilter{
		Type:    d.Get("type").(string),
		Value:   d.Get("value").(string),
		Enabled: d.Get("enabled").(bool),
		Comment: d.Get("comment").(string),
	}

	if d.Get("filter_id").(int) > 0 {
		filter.ID = d.Get("filter_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			filter.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	filter.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	filter.Modified = modified

	expireDate, err := types.ParseDate(d.Get("expire_date").(string))
	if err != nil {
		return nil, err
	}
	filter.ExpireDate = expireDate

	return filter, nil
}

//
// findIPFilter ...
//
func findIPFilter(filterID int, meta interface{}, subDomainName string, params map[string]string) (*myrasec.IPFilter, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	params["pageSize"] = "50"
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListIPFilters(subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading IP filters",
				Detail:   err.Error(),
			})
			return nil, diags
		}

		for _, f := range res {
			if f.ID == filterID {
				return &f, diags
			}
		}

		if len(res) < 50 {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find IP filter",
		Detail:   fmt.Sprintf("Unable to find IP filter with ID = [%d]", filterID),
	})
	return nil, diags
}
