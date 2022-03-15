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
)

//
// resourceMyrasecDomain ...
//
func resourceMyrasecDomain() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecDomainCreate,
		ReadContext:   resourceMyrasecDomainRead,
		UpdateContext: resourceMyrasecDomainUpdate,
		DeleteContext: resourceMyrasecDomainDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecDomainImport,
		},
		Schema: map[string]*schema.Schema{
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the domain.",
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
			"name": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "Domain name.",
			},
			"auto_update": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Auto update flag for the domain.",
			},
			"paused": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Shows if Myra is paused for this domain.",
			},
			"paused_until": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Date until Myra will be automatically reactivated.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecDomainCreate ...
//
func resourceMyrasecDomainCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	domain, err := buildDomain(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building domain",
			Detail:   err.Error(),
		})
		return diags
	}

	resp, err := client.CreateDomain(domain)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating domain",
			Detail:   err.Error(),
		})
		return diags
	}
	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecDomainRead(ctx, d, meta)
}

//
// resourceMyrasecDomainRead ...
//
func resourceMyrasecDomainRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	domainID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing domain ID",
			Detail:   err.Error(),
		})
		return diags
	}

	domain, diags := findDomain(domainID, meta)
	if diags.HasError() || domain == nil {
		return diags
	}

	d.SetId(strconv.Itoa(domainID))
	d.Set("domain_id", domain.ID)
	d.Set("name", domain.Name)
	d.Set("auto_update", domain.AutoUpdate)
	d.Set("paused", domain.Paused)
	d.Set("paused_until", domain.PausedUntil)
	d.Set("created", domain.Created.Format(time.RFC3339))
	d.Set("modified", domain.Modified.Format(time.RFC3339))

	return diags
}

//
// resourceMyrasecDomainUpdate ...
//
func resourceMyrasecDomainUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	domain, err := buildDomain(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building domain",
			Detail:   err.Error(),
		})
		return diags
	}

	resp, err := client.UpdateDomain(domain)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating domain",
			Detail:   err.Error(),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecDomainRead(ctx, d, meta)
}

//
// resourceMyrasecDomainDelete ...
//
func resourceMyrasecDomainDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	domainID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing domain ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Deleting Domain: %v", domainID)

	domain, err := buildDomain(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building domain",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.DeleteDomain(domain)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting domain",
			Detail:   err.Error(),
		})
		return diags
	}
	return diags
}

//
// resourceMyrasecDomainImport ...
//
func resourceMyrasecDomainImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	domainID, err := strconv.Atoi(d.Id())
	if err != nil {
		return nil, err
	}

	domain, diags := findDomain(domainID, meta)
	if diags.HasError() || domain == nil {
		return nil, fmt.Errorf("Unable to find domain with ID = [%d]", domainID)
	}

	d.SetId(strconv.Itoa(domainID))
	d.Set("domain_id", domain.ID)

	resourceMyrasecDomainRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

//
// buildDomain ...
//
func buildDomain(d *schema.ResourceData, meta interface{}) (*myrasec.Domain, error) {
	domain := &myrasec.Domain{
		Name:       d.Get("name").(string),
		AutoUpdate: d.Get("auto_update").(bool),
		AutoDNS:    false,
		Paused:     d.Get("paused").(bool),
	}

	if d.Get("domain_id").(int) > 0 {
		domain.ID = d.Get("domain_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			domain.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	domain.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	domain.Modified = modified

	pausedUntil, err := types.ParseDate(d.Get("paused_until").(string))
	if err != nil {
		return nil, err
	}
	domain.PausedUntil = pausedUntil

	return domain, nil
}

//
// findDomain ...
//
func findDomain(domainID int, meta interface{}) (*myrasec.Domain, diag.Diagnostics) {
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
		res, err := client.ListDomains(params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading domains",
				Detail:   err.Error(),
			})
			return nil, diags
		}

		for _, d := range res {
			if d.ID == domainID {
				return &d, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find domain",
		Detail:   fmt.Sprintf("Unable to find domain with ID = [%d]", domainID),
	})
	return nil, diags
}
