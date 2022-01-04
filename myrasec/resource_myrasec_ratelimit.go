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
// resourceMyrasecRateLimit ...
//
func resourceMyrasecRateLimit() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecRateLimitCreate,
		ReadContext:   resourceMyrasecRateLimitRead,
		UpdateContext: resourceMyrasecRateLimitUpdate,
		DeleteContext: resourceMyrasecRateLimitDelete,
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
				Description: "The Subdomain for the rate limit setting.",
			},
			"ratelimit_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the rate limit setting.",
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
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Type of the rate limit setting.",
			},
			"network": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "Network in CIDR notation affected by the rate limiter.",
			},
			"value": {
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntInSlice([]int{4000, 2000, 1000, 500, 100, 60, 0}),
				Default:      1000,
				Description:  "Maximum amount of requests for the given network.",
			},
			"burst": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     50,
				Description: "Burst defines how many requests a client can make in excess of the specified rate.",
			},
			"timeframe": {
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntInSlice([]int{1, 2, 5, 10, 15, 30, 45, 60, 120, 180, 300, 600, 1200, 3600}),
				Default:      60,
				Description:  "The affected timeframe in seconds for the rate limit.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecRateLimitCreate ...
//
func resourceMyrasecRateLimitCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building rate limit setting",
			Detail:   err.Error(),
		})
		return diags
	}

	resp, err := client.CreateRateLimit(ratelimit)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating rate limit setting",
			Detail:   err.Error(),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecRateLimitRead(ctx, d, meta)
}

//
// resourceMyrasecRateLimitRead ...
//
func resourceMyrasecRateLimitRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	var subDomainName string
	var rateLimitID int
	var err error

	name, ok := d.GetOk("subdomain_name")
	if ok && !strings.Contains(d.Id(), ":") {
		subDomainName = name.(string)
		rateLimitID, err = strconv.Atoi(d.Id())
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error parsing rate limit setting ID",
				Detail:   err.Error(),
			})
			return diags
		}

	} else {
		subDomainName, rateLimitID, err = parseResourceServiceID(d.Id())
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error parsing rate limit setting ID",
				Detail:   err.Error(),
			})
			return diags
		}
	}

	d.SetId(strconv.Itoa(rateLimitID))

	ratelimits, err := client.ListRateLimits("dns", map[string]string{"subDomainName": subDomainName})
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching rate limit settings",
			Detail:   err.Error(),
		})
		return diags
	}

	for _, r := range ratelimits {
		if r.ID != rateLimitID {
			continue
		}
		d.Set("ratelimit_id", r.ID)
		d.Set("created", r.Created.Format(time.RFC3339))
		d.Set("modified", r.Modified.Format(time.RFC3339))
		d.Set("type", r.Type)
		d.Set("network", r.Network)
		d.Set("value", r.Value)
		d.Set("burst", r.Burst)
		d.Set("timeframe", r.Timeframe)
		d.Set("subdomain_name", r.SubDomainName)

		break
	}

	return diags
}

//
// resourceMyrasecRateLimitUpdate ...
//
func resourceMyrasecRateLimitUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	rateLimitID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing rate limit ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Updating rate limit setting: %v", rateLimitID)

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building rate limit setting",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.UpdateRateLimit(ratelimit)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating rate limit setting",
			Detail:   err.Error(),
		})
		return diags
	}
	return resourceMyrasecRateLimitRead(ctx, d, meta)
}

//
// resourceMyrasecRateLimitDelete ...
//
func resourceMyrasecRateLimitDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	rateLimitID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing rate limit ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Deleting rate limit setting: %v", rateLimitID)

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building rate limit setting",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.DeleteRateLimit(ratelimit)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting rate limit setting",
			Detail:   err.Error(),
		})
		return diags
	}
	return diags
}

//
// buildRateLimit ...
//
func buildRateLimit(d *schema.ResourceData, meta interface{}) (*myrasec.RateLimit, error) {
	ratelimit := &myrasec.RateLimit{
		Type:          d.Get("type").(string),
		Network:       d.Get("network").(string),
		SubDomainName: d.Get("subdomain_name").(string),
		Value:         d.Get("value").(int),
		Burst:         d.Get("burst").(int),
		Timeframe:     d.Get("timeframe").(int),
	}

	if d.Get("ratelimit_id").(int) > 0 {
		ratelimit.ID = d.Get("ratelimit_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			ratelimit.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	ratelimit.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	ratelimit.Modified = modified

	return ratelimit, nil
}
