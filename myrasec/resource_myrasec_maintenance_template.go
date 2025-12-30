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
)

// resourceMyrasecMaintenanceTemplate ...
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
				StateFunc: func(i any) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Domain for the maintenance template.",
			},
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Stores domain Id for subdomain.",
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
				Required:    true,
				Description: "Name of the maintenance template.",
			},
			"content": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "HTML content of the maintenance template.",
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					oldHash := d.Get("content_hash")
					newHash := createContentHash(newValue)
					return oldHash == newHash
				},
			},
			"content_hash": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecMaintenanceTemplateCreate ...
func resourceMyrasecMaintenanceTemplateCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	template, err := buildMaintenanceTemplate(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	resp, err := client.CreateMaintenanceTemplate(template, domainID)
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

// resourceMyrasecMaintenanceTemplateRead ...
func resourceMyrasecMaintenanceTemplateRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	template, diags := findMaintenanceTemplate(maintenanceTemplateID, meta, domainID)
	if diags.HasError() {
		return diags
	}

	if template == nil {
		d.SetId("")
		return nil
	}

	setMaintenanceTemplateData(d, template, domainID)

	return diags
}

// resourceMyrasecMaintenanceTemplateUpdate ...
func resourceMyrasecMaintenanceTemplateUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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

	template, err := buildMaintenanceTemplate(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	template, err = client.UpdateMaintenanceTemplate(template, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	setMaintenanceTemplateData(d, template, domainID)

	return diags
}

// resourceMyrasecMaintenanceTemplateDelete ...
func resourceMyrasecMaintenanceTemplateDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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

	template, err := buildMaintenanceTemplate(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance template",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	_, err = client.DeleteMaintenanceTemplate(template, domainID)
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

// resourceMyrasecMaintenanceTemplateImport ...
func resourceMyrasecMaintenanceTemplateImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	domainName, maintenanceTemplateID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing maintenance template ID: [%s]", err.Error())
	}

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return nil, fmt.Errorf("unable to find domainID for domainName [%s]", domainName)
	}

	template, diags := findMaintenanceTemplate(maintenanceTemplateID, meta, domainID)
	if diags.HasError() || template == nil {
		return nil, fmt.Errorf("unable to find maintenance template for domain [%s] with ID = [%d]", domainName, maintenanceTemplateID)
	}

	d.SetId(strconv.Itoa(maintenanceTemplateID))
	d.Set("domain_name", domainName)
	d.Set("maintenance_id", template.ID)
	d.Set("name", template.Name)
	d.Set("content", "")
	d.Set("content_hash", createContentHash(template.Content))

	resourceMyrasecMaintenanceTemplateRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildMaintenanceTemplate ...
func buildMaintenanceTemplate(d *schema.ResourceData) (*myrasec.MaintenanceTemplate, error) {
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

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	template.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	template.Modified = modified

	return template, nil
}

// findMaintenanceTemplate ...
func findMaintenanceTemplate(maintenanceTemplateID int, meta any, domainID int) (*myrasec.MaintenanceTemplate, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	pageSize := 100
	params := map[string]string{
		"pageSize": strconv.Itoa(pageSize),
		"page":     strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListMaintenanceTemplates(domainID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading maintenance template",
				Detail:   formatError(err),
			})
			return nil, diags
		}

		for _, mt := range res {
			if mt.ID == maintenanceTemplateID {
				return &mt, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}
	return nil, diags
}

// setMaintenanceTemplateData ...
func setMaintenanceTemplateData(d *schema.ResourceData, template *myrasec.MaintenanceTemplate, domainID int) {
	d.SetId(strconv.Itoa(template.ID))
	d.Set("maintenance_template_id", template.ID)
	d.Set("created", template.Created.Format(time.RFC3339))
	d.Set("modified", template.Modified.Format(time.RFC3339))
	d.Set("name", template.Name)
	d.Set("content", "")
	d.Set("content_hash", createContentHash(template.Content))
	d.Set("domain_id", domainID)
}
