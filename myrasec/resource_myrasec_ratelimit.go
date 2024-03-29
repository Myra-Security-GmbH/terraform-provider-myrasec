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

// resourceMyrasecRateLimit ...
func resourceMyrasecRateLimit() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecRateLimitCreate,
		ReadContext:   resourceMyrasecRateLimitRead,
		UpdateContext: resourceMyrasecRateLimitUpdate,
		DeleteContext: resourceMyrasecRateLimitDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecRateLimitImport,
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

// resourceMyrasecRateLimitCreate ...
func resourceMyrasecRateLimitCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building rate limit setting",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	resp, err := client.CreateRateLimit(ratelimit, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating rate limit setting",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecRateLimitRead(ctx, d, meta)
}

// resourceMyrasecRateLimitRead ...
func resourceMyrasecRateLimitRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	rateLimitID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing rate limit setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	rateLimit, diags := findRateLimit(rateLimitID, meta, subDomainName, domainID)
	if diags.HasError() || rateLimit == nil {
		return diags
	}

	setRateLimitData(d, rateLimit, domainID)

	return diags
}

// resourceMyrasecRateLimitUpdate ...
func resourceMyrasecRateLimitUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	rateLimitID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing rate limit ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating rate limit setting: %v", rateLimitID)

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building rate limit setting",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	ratelimit, err = client.UpdateRateLimit(ratelimit, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating rate limit setting",
			Detail:   formatError(err),
		})
		return diags
	}

	setRateLimitData(d, ratelimit, domainID)

	return diags
}

// resourceMyrasecRateLimitDelete ...
func resourceMyrasecRateLimitDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	rateLimitID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing rate limit ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting rate limit setting: %v", rateLimitID)

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building rate limit setting",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	_, err = client.DeleteRateLimit(ratelimit, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting rate limit setting",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecRateLimitImport ...
func resourceMyrasecRateLimitImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	subDomainName, rateLimitID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing rate limit ID: [%s]", err.Error())
	}

	domain, diags := findDomainBySubdomainName(meta, subDomainName)
	if diags != nil {
		return nil, fmt.Errorf("unable to find domain for subdomain: [%s]", subDomainName)
	}

	rateLimit, diags := findRateLimit(rateLimitID, meta, subDomainName, domain.ID)
	if diags.HasError() || rateLimit == nil {
		return nil, fmt.Errorf("unable to find rate limit for subdomain [%s] with ID = [%d]", subDomainName, rateLimitID)
	}

	d.SetId(strconv.Itoa(rateLimitID))
	d.Set("ratelimit_id", rateLimit.ID)
	d.Set("subdomain_name", rateLimit.SubDomainName)

	resourceMyrasecRateLimitRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildRateLimit ...
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

// findRateLimit ...
func findRateLimit(rateLimitID int, meta interface{}, subDomainName string, domainID int) (*myrasec.RateLimit, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	pageSize := 250
	params := map[string]string{
		"subDomainName": subDomainName,
		"pageSize":      strconv.Itoa(pageSize),
		"page":          strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListRateLimits(domainID, subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading rate limits",
				Detail:   formatError(err),
			})
			return nil, diags
		}

		for _, r := range res {
			if r.ID == rateLimitID {
				return &r, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find rate limit",
		Detail:   fmt.Sprintf("Unable to find rate limit with ID = [%d]", rateLimitID),
	})
	return nil, diags
}

// setRateLimitData ...
func setRateLimitData(d *schema.ResourceData, rateLimit *myrasec.RateLimit, domainID int) {
	d.SetId(strconv.Itoa(rateLimit.ID))
	d.Set("ratelimit_id", rateLimit.ID)
	d.Set("created", rateLimit.Created.Format(time.RFC3339))
	d.Set("modified", rateLimit.Modified.Format(time.RFC3339))
	d.Set("type", rateLimit.Type)
	d.Set("network", rateLimit.Network)
	d.Set("value", rateLimit.Value)
	d.Set("burst", rateLimit.Burst)
	d.Set("timeframe", rateLimit.Timeframe)
	d.Set("subdomain_name", rateLimit.SubDomainName)
	d.Set("domain_id", domainID)
}
