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

// resourceMyrasecIPFilter ...
func resourceMyrasecIPFilter() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecIPFilterCreate,
		ReadContext:   resourceMyrasecIPFilterRead,
		UpdateContext: resourceMyrasecIPFilterUpdate,
		DeleteContext: resourceMyrasecIPFilterDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecIPFilterImport,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					name := i.(string)
					if myrasec.IsGeneralDomainName(name) {
						return name
					}
					return strings.ToLower(name)
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new)
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
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Stores domain Id for subdomain.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecIPFilterCreate ...
func resourceMyrasecIPFilterCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building IP filter",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}
	resp, err := client.CreateIPFilter(filter, domainID, subDomainName)
	if err == nil {
		setIPFilterData(d, resp, domainID)
		return diags
	}

	filter, errImport := importExistingIPFilter(filter, domainID, meta)
	if errImport != nil {
		log.Printf("[DEBUG] auto-import failed: %s", errImport)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating IP filter",
			Detail:   formatError(err),
		})
		return diags
	}

	setIPFilterData(d, filter, domainID)
	return diags
}

// resourceMyrasecIPFilterRead ...
func resourceMyrasecIPFilterRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	filterID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing IP filter ID",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	filter, diags := findIPFilter(filterID, meta, subDomainName, domainID)
	if filter == nil {
		d.SetId("")
		return nil
	}

	setIPFilterData(d, filter, domainID)

	return diags
}

// resourceMyrasecIPFilterUpdate ...
func resourceMyrasecIPFilterUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	filterID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing IP filter ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating IP filter: %v", filterID)

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building IP filter",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	filter, err = client.UpdateIPFilter(filter, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating IP filter",
			Detail:   formatError(err),
		})
		return diags
	}

	setIPFilterData(d, filter, domainID)

	return diags
}

// resourceMyrasecIPFilterDelete ...
func resourceMyrasecIPFilterDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	filterID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing IP filter ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting IP filter: %v", filterID)

	filter, err := buildIPFilter(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building IP filter",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	_, err = client.DeleteIPFilter(filter, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting IP filter",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecIPFilterImport ...
func resourceMyrasecIPFilterImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	subDomainName, filterID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing IP filter ID: [%s]", err.Error())
	}

	domain, diags := findDomainBySubdomainName(meta, subDomainName)
	if diags != nil {
		return nil, fmt.Errorf("unable to find domain for subdomain: [%s]", subDomainName)
	}

	filter, diags := findIPFilter(filterID, meta, subDomainName, domain.ID)
	if diags.HasError() || filter == nil {
		return nil, fmt.Errorf("unable to find IP filter for subdomain [%s] with ID = [%d]", subDomainName, filterID)
	}

	d.SetId(strconv.Itoa(filterID))
	d.Set("filter_id", filter.ID)
	d.Set("subdomain_name", subDomainName)

	resourceMyrasecIPFilterRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildIPFilter ...
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

// findIPFilter ...
func findIPFilter(filterID int, meta interface{}, subDomainName string, domainId int) (*myrasec.IPFilter, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	f, err := client.GetIPFilter(domainId, subDomainName, filterID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error loading IP filter",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	if f != nil {
		return f, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find IP filter",
		Detail:   fmt.Sprintf("Unable to find IP filter with ID = [%d]", filterID),
	})
	return nil, diags
}

// setIPFilterData ...
func setIPFilterData(d *schema.ResourceData, filter *myrasec.IPFilter, domainId int) {
	d.SetId(strconv.Itoa(filter.ID))
	d.Set("filter_id", filter.ID)
	d.Set("created", filter.Created.Format(time.RFC3339))
	d.Set("modified", filter.Modified.Format(time.RFC3339))
	d.Set("type", filter.Type)
	d.Set("value", filter.Value)
	d.Set("enabled", filter.Enabled)
	d.Set("comment", filter.Comment)
	d.Set("subdomain_name", filter.SubDomainName)
	d.Set("domain_id", domainId)

	if filter.ExpireDate != nil {
		d.Set("expire_date", filter.ExpireDate.Format(time.RFC3339))
	}
}

// importExistingIPFilter ...
func importExistingIPFilter(filter *myrasec.IPFilter, domainId int, meta interface{}) (*myrasec.IPFilter, error) {
	client := meta.(*myrasec.API)

	s := strings.Split(filter.Value, "/")
	if len(s) != 2 {
		return nil, fmt.Errorf("invalid IP Filter value [%s] passed for automatic import", filter.Value)
	}

	params := map[string]string{
		"type":   filter.Type,
		"search": s[0],
	}

	filters, err := client.ListIPFilters(domainId, filter.SubDomainName, params)
	if err != nil {
		return nil, err
	}

	if len(filters) <= 0 {
		return nil, fmt.Errorf("unable to find existing IP filter for automatic import")
	}

	for _, f := range filters {
		if f.Value != filter.Value ||
			f.Type != filter.Type ||
			f.Enabled != filter.Enabled {
			continue
		}

		return &f, nil
	}

	return nil, fmt.Errorf("unable to find existing IP filter for automatic import")
}
