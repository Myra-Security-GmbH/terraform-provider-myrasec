package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

//
// resourceMyrasecRedirect ...
//
func resourceMyrasecRedirect() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecRedirectCreate,
		ReadContext:   resourceMyrasecRedirectRead,
		UpdateContext: resourceMyrasecRedirectUpdate,
		DeleteContext: resourceMyrasecRedirectDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecRedirectImport,
		},
		Schema: map[string]*schema.Schema{
			"redirect_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the redirect.",
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
			"matching_type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"exact", "prefix", "suffix"}, false),
				Description:  "Type to match the redirect.",
			},
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					name := i.(string)
					if isGeneralDomainName(name) {
						return name
					}
					return strings.ToLower(name)
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return removeTrailingDot(old) == removeTrailingDot(new)
				},
				Description: "The Subdomain for the redirect.",
			},
			"source": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Location to match against.",
			},
			"destination": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target where redirect should point to.",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "A comment to describe this redirect.",
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"permanent", "redirect"}, false),
				Description:  "Type of redirection.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Define wether this redirect is enabled or not.",
			},
			"sort": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     0,
				Description: "The ascending order for the redirect rules.",
			},
			"expert_mode": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Disable redirect loop detection.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecRedirectCreate ...
//
func resourceMyrasecRedirectCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	redirect, err := buildRedirect(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building redirect",
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

	resp, err := client.CreateRedirect(redirect, domain.ID, subDomainName)
	if err == nil {
		d.SetId(fmt.Sprintf("%d", resp.ID))
		return resourceMyrasecRedirectRead(ctx, d, meta)
	}

	redirect, errImport := importExistingRedirect(redirect, domain.ID, subDomainName, meta)
	if errImport != nil {
		log.Printf("[DEBUG] auto-import failed: %s", errImport)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error creating redirect",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", redirect.ID))
	return resourceMyrasecRedirectRead(ctx, d, meta)
}

//
// resourceMyrasecRedirectRead ...
//
func resourceMyrasecRedirectRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
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
	redirectID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing redirect ID",
			Detail:   formatError(err),
		})
		return diags
	}

	redirect, diags := findRedirect(redirectID, meta, subDomainName)
	if diags.HasError() || redirect == nil {
		return diags
	}

	setRedirectData(d, redirect)

	return diags
}

//
// resourceMyrasecRedirectUpdate ...
//
func resourceMyrasecRedirectUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	redirectID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing redirect ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating redirect: %v", redirectID)

	redirect, err := buildRedirect(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building redirect",
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

	redirect, err = client.UpdateRedirect(redirect, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating redirect",
			Detail:   formatError(err),
		})
		return diags
	}

	setRedirectData(d, redirect)

	return diags
}

//
// resourceMyrasecRedirectDelete ...
//
func resourceMyrasecRedirectDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	redirectID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing redirect ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting redirect: %v", redirectID)

	redirect, err := buildRedirect(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building redirect",
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

	_, err = client.DeleteRedirect(redirect, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting redirect",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

//
// resourceMyrasecRedirectImport ...
//
func resourceMyrasecRedirectImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	subDomainName, redirectID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing redirect ID: [%s]", err.Error())
	}

	redirect, diags := findRedirect(redirectID, meta, subDomainName)
	if diags.HasError() || redirect == nil {
		return nil, fmt.Errorf("unable to find redirect for subdomain [%s] with ID = [%d]", subDomainName, redirectID)
	}

	d.SetId(strconv.Itoa(redirectID))
	d.Set("redirect_id", redirect.ID)
	d.Set("subdomain_name", redirect.SubDomainName)

	resourceMyrasecRedirectRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

//
// buildRedirect ...
//
func buildRedirect(d *schema.ResourceData, meta interface{}) (*myrasec.Redirect, error) {
	redirect := &myrasec.Redirect{
		Type:          d.Get("type").(string),
		MatchingType:  d.Get("matching_type").(string),
		SubDomainName: d.Get("subdomain_name").(string),
		Source:        d.Get("source").(string),
		Destination:   d.Get("destination").(string),
		Comment:       d.Get("comment").(string),
		Sort:          d.Get("sort").(int),
		Enabled:       d.Get("enabled").(bool),
		ExpertMode:    d.Get("expert_mode").(bool),
	}

	if d.Get("redirect_id").(int) > 0 {
		redirect.ID = d.Get("redirect_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			redirect.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	redirect.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	redirect.Modified = modified

	return redirect, nil
}

//
// findRedirect ...
//
func findRedirect(redirectID int, meta interface{}, subDomainName string) (*myrasec.Redirect, diag.Diagnostics) {
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

	r, err := client.GetRedirect(domain.ID, subDomainName, redirectID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error loading redirect",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	if r != nil {
		return r, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find redirect",
		Detail:   fmt.Sprintf("Unable to find redirect with ID = [%d]", redirectID),
	})
	return nil, diags
}

//
// setRedirectData ...
//
func setRedirectData(d *schema.ResourceData, redirect *myrasec.Redirect) {
	d.SetId(strconv.Itoa(redirect.ID))
	d.Set("redirect_id", redirect.ID)
	d.Set("created", redirect.Created.Format(time.RFC3339))
	d.Set("modified", redirect.Modified.Format(time.RFC3339))
	d.Set("type", redirect.Type)
	d.Set("subdomain_name", redirect.SubDomainName)
	d.Set("source", redirect.Source)
	d.Set("destination", redirect.Destination)
	d.Set("comment", redirect.Comment)
	d.Set("sort", redirect.Sort)
	d.Set("matching_type", redirect.MatchingType)
	d.Set("enabled", redirect.Enabled)
}

//
// importExistingRedirect ...
//
func importExistingRedirect(redirect *myrasec.Redirect, domainId int, subDomainName string, meta interface{}) (*myrasec.Redirect, error) {
	client := meta.(*myrasec.API)

	params := map[string]string{
		"search": redirect.Source,
	}

	redirects, err := client.ListRedirects(domainId, subDomainName, params)
	if err != nil {
		return nil, err
	}

	if len(redirects) <= 0 {
		return nil, fmt.Errorf("unable to find existing redirect for automatic import")
	}

	for _, r := range redirects {
		if r.Source != redirect.Source ||
			r.Destination != redirect.Destination {
			continue
		}

		return &r, nil
	}
	return nil, fmt.Errorf("unable to find existing redirect for automatic import")
}
