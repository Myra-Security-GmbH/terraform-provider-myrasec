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
			StateContext: schema.ImportStatePassthroughContext,
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

	domains, err := client.ListDomains(nil)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domains",
			Detail:   err.Error(),
		})
		return diags
	}

	for _, r := range domains {
		if r.ID != domainID {
			continue
		}
		d.Set("domain_id", r.ID)
		d.Set("name", r.Name)
		d.Set("auto_update", r.AutoUpdate)
		d.Set("paused", r.Paused)
		d.Set("paused_until", r.PausedUntil)
		d.Set("created", r.Created.Format(time.RFC3339))
		d.Set("modified", r.Modified.Format(time.RFC3339))
		break
	}

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
			Summary:  "Error parsing domain id",
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
