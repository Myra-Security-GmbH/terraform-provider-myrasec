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

// resourceMyrasecErrorPage ...
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
					name := i.(string)
					if myrasec.IsGeneralDomainName(name) {
						return name
					}
					return myrasec.RemoveTrailingDot(strings.ToLower(name))
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new)
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
				ForceNew:     true,
			},
			"content": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "HTML content of the error page.",
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return strings.TrimSpace(newValue) == strings.TrimSpace(oldValue)
				},
			},
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Stores domain ID of the subdomain.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecErrorPageCreate ...
func resourceMyrasecErrorPageCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	errorPage, err := buildErrorPage(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building error page",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, diags := findDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	_, err = client.CreateErrorPage(errorPage, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating error page",
			Detail:   formatError(err),
		})
		return diags
	}
	client.PruneCache()

	return resourceMyrasecErrorPageRead(ctx, d, meta)
}

// resourceMyrasecErrorPageRead ...
func resourceMyrasecErrorPageRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	errorCode := d.Get("error_code").(int)

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	errorPage, diags := findErrorPageByErrorCode(subDomainName, errorCode, meta, domainID)
	if errorPage == nil {
		d.SetId("")
		return nil
	}
	if diags.HasError() {
		return diags
	}

	setErrorPageData(d, errorPage, domainID)

	return diags
}

// resourceMyrasecErrorPageUpdate ...
func resourceMyrasecErrorPageUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	errorPage, err := buildErrorPage(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building error page",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, diags := findDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	errorPage, err = client.UpdateErrorPage(errorPage, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating error page",
			Detail:   formatError(err),
		})
		return diags
	}

	setErrorPageData(d, errorPage, domainID)

	return diags
}

// resourceMyrasecErrorPageDelete ...
func resourceMyrasecErrorPageDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	pageId, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing error page ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting error page: %v", pageId)

	errorPage, err := buildErrorPage(d, meta)
	errorPage.ID = pageId
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building error page",
			Detail:   formatError(err),
		})
		return diags
	}

	if errorPage.ID == 0 {
		return diags
	}

	domainID, diags := findDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	_, err = client.DeleteErrorPage(errorPage, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting error page",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecErrorPageImport ...
func resourceMyrasecErrorPageImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	subDomainName, id, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing ID or error code: [%s]", err.Error())
	}

	var errorPage *myrasec.ErrorPage

	domain, diags := findDomainBySubdomainName(meta, subDomainName)
	if diags.HasError() {
		return nil, fmt.Errorf("unable to find domain for subdomain [%s]", subDomainName)
	}

	if IntInSlice(id, []int{400, 405, 429, 500, 502, 503, 504, 9999}) {
		errorPage, diags = findErrorPageByErrorCode(subDomainName, id, meta, domain.ID)
	} else {
		errorPage, diags = findErrorPageByID(subDomainName, id, meta, domain.ID)
	}

	if diags.HasError() || errorPage == nil {
		return nil, fmt.Errorf("unable to find error page [%d] for subdomain [%s]", id, subDomainName)
	}

	d.SetId(strconv.Itoa(errorPage.ID))
	d.Set("error_code", errorPage.ErrorCode)
	d.Set("content", errorPage.Content)
	d.Set("subdomain_name", errorPage.SubDomainName)
	d.Set("created", errorPage.Created)
	d.Set("modified", errorPage.Modified)

	resourceMyrasecErrorPageRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildErrorPage ...
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

// findErrorPageByErrorCode ...
func findErrorPageByErrorCode(subDomainName string, code int, meta interface{}, domainID int) (*myrasec.ErrorPage, diag.Diagnostics) {
	return findErrorPage(subDomainName, code, true, meta, domainID)
}

// findErrorPageByID ...
func findErrorPageByID(subDomainName string, id int, meta interface{}, domainID int) (*myrasec.ErrorPage, diag.Diagnostics) {
	return findErrorPage(subDomainName, id, false, meta, domainID)
}

// findErrorPage ...
func findErrorPage(subDomainName string, id int, idIsCode bool, meta interface{}, domainID int) (*myrasec.ErrorPage, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	pageSize := 250
	params := map[string]string{
		"pageSize": strconv.Itoa(pageSize),
		"page":     strconv.Itoa(page),
		"search":   myrasec.RemoveTrailingDot(subDomainName),
	}
	for {
		params["page"] = strconv.Itoa(page)
		pages, err := client.ListErrorPages(domainID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading error pages",
				Detail:   formatError(err),
			})
			return nil, diags
		}

		for _, ep := range pages {
			if myrasec.EnsureTrailingDot(ep.SubDomainName) == myrasec.EnsureTrailingDot(subDomainName) &&
				((idIsCode && ep.ErrorCode == id) || (!idIsCode && ep.ID == id)) {

				epx, err := client.GetErrorPage(domainID, ep.ID)
				if err != nil {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Error,
						Summary:  "Error loading error page content",
						Detail:   formatError(err),
					})
				}

				return epx, diags
			}
		}
		if len(pages) < pageSize {
			break
		}
		page++

	}
	return nil, diags
}

// setErrorPageData ...
func setErrorPageData(d *schema.ResourceData, errorPage *myrasec.ErrorPage, domainID int) {
	d.SetId(strconv.Itoa(errorPage.ID))
	d.Set("error_code", errorPage.ErrorCode)
	d.Set("content", errorPage.Content)
	d.Set("subdomain_name", errorPage.SubDomainName)
	d.Set("created", errorPage.Created.Format(time.RFC3339))
	d.Set("modified", errorPage.Modified.Format(time.RFC3339))
	d.Set("domain_id", domainID)
}
