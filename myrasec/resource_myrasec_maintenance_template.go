package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// resourceMyrasecMaintenanceTemplate ...
//
func resourceMyrasecMaintenanceTemplate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecMaintenanceTemplateCreate,
		ReadContext:   resourceMyrasecMaintenanceTemplateRead,
		UpdateContext: resourceMyrasecMaintenanceTemplateUpdate,
		DeleteContext: resourceMyrasecMaintenanceTemplateDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecMaintenanceTemplateImport,
		},
		Schema: map[string]*schema.Schema{
			"domain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Domain for the maintenance template.",
			},
			"maintenance_template_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the maintenance template",
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
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the maintenance template.",
			},
			"content": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "HTML content of the maintenance template.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecMaintenanceTemplateCreate ...
//
func resourceMyrasecMaintenanceTemplateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	template, err := buildMaintenanceTemplate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)
	domain, err := fetchDomain(client, domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVE
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.CreateMaintenanceTemplate(template, domain.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}
	d.SetId(fmt.Sprintf("%d", resp.ID))

	return resourceMyrasecMaintenanceTemplateRead(ctx, d, meta)
}

//
// resourceMyrasecMaintenanceTemplateRead ...
//
func resourceMyrasecMaintenanceTemplateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("domain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[domain_name] is not set")),
		})
	}

	domainName := name.(string)
	maintenanceTemplateID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing maintenance template id",
			Detail:   formatError(err),
		})
		return diags
	}

	template, diags := findMaintenanceTemplate(maintenanceTemplateID, meta, domainName)
	if diags.HasError() || template == nil {
		return diags
	}

	setMaintenanceTemplateData(d, template)

	return diags
}

//
// resourceMyrasecMaintenanceTemplateUpdate ...
//
func resourceMyrasecMaintenanceTemplateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	maintenanceTemplateID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing maintenance template ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating maintenance template: %v", maintenanceTemplateID)

	template, err := buildMaintenanceTemplate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)
	domain, err := fetchDomain(client, domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVE
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	template, err = client.UpdateMaintenanceTemplate(template, domain.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	setMaintenanceTemplateData(d, template)

	return diags
}

//
// resourceMyrasecMaintenanceTemplateDelete ...
//
func resourceMyrasecMaintenanceTemplateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	maintenanceTemplateID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing maintenance template ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting maintenance template: %v", maintenanceTemplateID)

	template, err := buildMaintenanceTemplate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)
	domain, err := fetchDomain(client, domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.DeleteMaintenanceTemplate(template, domain.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

//
// resourceMyrasecMaintenanceTemplateImport ...
//
func resourceMyrasecMaintenanceTemplateImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	domainName, maintenanceTemplateID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing maintenance template ID: [%s]", err.Error())
	}

	template, diags := findMaintenanceTemplate(maintenanceTemplateID, meta, domainName)
	if diags.HasError() || template == nil {
		return nil, fmt.Errorf("unable to find maintenance template for domain [%s] with ID = [%d]", domainName, maintenanceTemplateID)
	}

	d.SetId(strconv.Itoa(maintenanceTemplateID))
	d.Set("domain_name", domainName)
	d.Set("maintenance_id", template.ID)
	d.Set("name", template.Name)
	d.Set("content", template.Content)

	resourceMyrasecMaintenanceTemplateRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

//
// buildMaintenanceTemplate ...
//
func buildMaintenanceTemplate(d *schema.ResourceData, meta interface{}) (*myrasec.MaintenanceTemplate, error) {
	template := &myrasec.MaintenanceTemplate{
		Content: d.Get("content").(string),
		Name:    d.Get("name").(string),
	}

	if d.Get("maintenance_template_id").(int) > 0 {
		template.ID = d.Get("maintenance_template_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			template.ID = id
		}
	}

	return template, nil
}

//
// findMaintenanceTemplate ...
//
func findMaintenanceTemplate(maintenanceTemplateID int, meta interface{}, domainName string) (*myrasec.MaintenanceTemplate, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	domain, err := fetchDomain(client, domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	page := 1
	pageSize := 100
	params := map[string]string{
		"pageSize": strconv.Itoa(pageSize),
		"page":     strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListMaintenanceTemplates(domain.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading maintenance template",
				Detail:   formatError(err),
			})
			return nil, diags
		}

		for _, m := range res {
			if m.ID == maintenanceTemplateID {
				return &m, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find maintenance template",
		Detail:   fmt.Sprintf("Unable to find maintenance template with ID = [%d]", maintenanceTemplateID),
	})
	return nil, diags
}

//
// setMaintenanceTemplateData ...
//
func setMaintenanceTemplateData(d *schema.ResourceData, template *myrasec.MaintenanceTemplate) {
	d.SetId(strconv.Itoa(template.ID))
	d.Set("maintenance_template_id", template.ID)
	d.Set("created", template.Created.Format(time.RFC3339))
	d.Set("modified", template.Modified.Format(time.RFC3339))
	d.Set("name", template.Name)
	d.Set("content", template.Content)
}
