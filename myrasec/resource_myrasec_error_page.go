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
// resourceMyrasecErrorPage
//
func resourceMyrasecErrorPage() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecErrorPageCreate,
		ReadContext:   resourceMyrasecErrorPageRead,
		UpdateContext: resourceMyrasecErrorPageUpdate,
		DeleteContext: resourceMyrasecErrorPageDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecErrorPageImport,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the error page.",
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
			"error_code": {
				Type:         schema.TypeInt,
				Required:     true,
				Description:  "Error code of the error page.",
				ValidateFunc: validation.IntInSlice([]int{400, 405, 429, 500, 502, 503, 504, 9999}),
			},
			"content": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "HTML content of the error page.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecErrorPageCreate
//
func resourceMyrasecErrorPageCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	errorPage, err := buildErrorPage(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building error page",
			Detail:   err.Error(),
		})
		return diags
	}

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   err.Error(),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.CreateErrorPage(errorPage, domain.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating error page",
			Detail:   err.Error(),
		})
		return diags
	}

	return resourceMyrasecErrorPageRead(ctx, d, meta)
}

//
// resourceMyrasecErrorPageRead
//
func resourceMyrasecErrorPageRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("subdomain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   "[subdomain_name] is not set",
		})
		return diags
	}

	subDomainName := name.(string)
	errorCode := d.Get("error_code").(int)

	errorPage, diags := findErrorPage(subDomainName, errorCode, meta)
	if diags.HasError() || errorPage == nil {
		return diags
	}

	d.SetId(strconv.Itoa(errorPage.ID))
	d.Set("error_code", errorPage.ErrorCode)
	d.Set("content", errorPage.Content)
	d.Set("subdomain_name", errorPage.SubDomainName)
	d.Set("created", errorPage.Created.Format(time.RFC3339))
	d.Set("modified", errorPage.Modified.Format(time.RFC3339))

	return diags
}

//
// resourceMyrasecErrorPageUpdate
//
func resourceMyrasecErrorPageUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	errorPage, err := buildErrorPage(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building error page",
			Detail:   err.Error(),
		})
		return diags
	}

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   err.Error(),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.UpdateErrorPage(errorPage, domain.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating error page",
			Detail:   err.Error(),
		})
		return diags
	}

	return resourceMyrasecErrorPageRead(ctx, d, meta)
}

//
// resourceMyrasecErrorPageDelete
//
func resourceMyrasecErrorPageDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	pageId, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing error page ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Deleting error page: %v", pageId)

	errorPage, err := buildErrorPage(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building error page",
			Detail:   err.Error(),
		})
		return diags
	}

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.DeleteErrorPage(errorPage, domain.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting error page",
			Detail:   err.Error(),
		})
		return diags
	}
	return diags
}

//
// resourceMyrasecErrorPageImport
//
func resourceMyrasecErrorPageImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	subDomainName, pageId, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing error page ID: [%s]", err.Error())
	}

	errorCode := d.Get("error_code").(int)
	errorPage, diags := findErrorPage(subDomainName, errorCode, meta)

	if diags.HasError() || errorPage == nil {
		return nil, fmt.Errorf("unable to find error page for subdomain [%s] with ID = [%d]", subDomainName, pageId)
	}

	d.SetId(strconv.Itoa(pageId))
	d.Set("error_code", errorPage.ErrorCode)
	d.Set("content", errorPage.Content)
	d.Set("subdomain_name", errorPage.SubDomainName)
	d.Set("created", errorPage.Created)
	d.Set("modified", errorPage.Modified)

	resourceMyrasecErrorPageRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

//
// buildErrorPage
//
func buildErrorPage(d *schema.ResourceData, meta interface{}) (*myrasec.ErrorPage, error) {

	errorPage := &myrasec.ErrorPage{
		Content:       d.Get("content").(string),
		ErrorCode:     d.Get("error_code").(int),
		SubDomainName: d.Get("subdomain_name").(string),
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	errorPage.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	errorPage.Modified = modified

	return errorPage, nil
}

//
// findErrorPage
//
func findErrorPage(subDomainName string, errorCode int, meta interface{}) (*myrasec.ErrorPage, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   err.Error(),
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
		domains, err := client.ListErrorPages(domain.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading error pages",
				Detail:   err.Error(),
			})
			return nil, diags
		}

		for _, ep := range domains {
			if ep.ErrorCode == errorCode && ep.SubDomainName == subDomainName {
				return &ep, diags
			}
		}
		if len(domains) < pageSize {
			break
		}
		page++

	}
	return nil, diags
}
