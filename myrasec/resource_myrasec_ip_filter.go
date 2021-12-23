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
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToUpper(i.(string))
				},
				ValidateFunc: validation.StringInSlice([]string{"BLACKLIST", "WHITELIST", "WHITELIST_REQUEST_LIMITER"}, false),
				Description:  "Type of the IP filter.",
			},
			"value": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The IP you want to whitelist or blacklist. By using CIDR notation on IPv4 IPs, you are able to define whole subnets.",
			},
			"expire_date": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Expire date schedules the deaktivation of the filter. If none is set, the filter will be active until manual deactivation.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Enable or disable a filter.",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				ForceNew:    true,
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
			Summary:  "Error building ip filter",
			Detail:   err.Error(),
		})
		return diags
	}

	resp, err := client.CreateIPFilter(filter, d.Get("subdomain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating filter",
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
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	subDomainName, filterID, err := parseResourceServiceID(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing ID",
			Detail:   err.Error(),
		})
		return diags
	}

	filters, err := client.ListIPFilters(subDomainName, nil)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching filters",
			Detail:   err.Error(),
		})
		return diags
	}

	for _, r := range filters {
		if r.ID != filterID {
			continue
		}
		d.Set("filter_id", r.ID)
		d.Set("created", r.Created.Format(time.RFC3339))
		d.Set("modified", r.Modified.Format(time.RFC3339))
		d.Set("type", r.Type)
		d.Set("value", r.Value)
		d.Set("enabled", r.Enabled)
		d.Set("comment", r.Comment)
		if r.ExpireDate != nil {
			d.Set("expire_date", r.ExpireDate.Format(time.RFC3339))
		}
		break
	}

	return diags
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
			Summary:  "Error parsing filter id",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Deleting ip filter: %v", filterID)

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building ip filter",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.DeleteIPFilter(filter, d.Get("subdomain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting ip filter",
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
