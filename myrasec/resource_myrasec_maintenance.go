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

// resourceMyrasecMaintenance ...
func resourceMyrasecMaintenance() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecMaintenanceCreate,
		ReadContext:   resourceMyrasecMaintenanceRead,
		UpdateContext: resourceMyrasecMaintenanceUpdate,
		DeleteContext: resourceMyrasecMaintenanceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecMaintenanceImport,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
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
				Description: "The subdomain name for this maintenance.",
			},
			"maintenance_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the maintenance",
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
			"start": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Start Date for the maintenance.",
			},
			"end": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "End Date for the maintenance.",
			},
			"content": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "HTML content of the maintenance.",
			},
			"active": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Status if the maintenance page is active or not.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecMaintenanceCreate
func resourceMyrasecMaintenanceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	maintenance, err := buildMaintenance(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance",
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

	// REMOVE
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.CreateMaintenance(maintenance, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating maintenance",
			Detail:   formatError(err),
		})
		return diags
	}
	d.SetId(fmt.Sprintf("%d", resp.ID))

	return resourceMyrasecMaintenanceRead(ctx, d, meta)
}

// resourceMyrasecMaintenanceRead
func resourceMyrasecMaintenanceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("subdomain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[subdomain_name] is not set")),
		})
	}

	subDomainName := name.(string)
	maintenanceID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing maintenance id",
			Detail:   formatError(err),
		})
		return diags
	}

	maintenance, diags := findMaintenance(maintenanceID, meta, subDomainName)
	if diags.HasError() || maintenance == nil {
		return diags
	}

	setMaintenanceData(d, maintenance)

	return diags
}

// resourceMyrasecMaintenanceUpdate ...
func resourceMyrasecMaintenanceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	maintenanceID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing maintenance ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating maintenance: %v", maintenanceID)

	maintenance, err := buildMaintenance(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance",
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

	// REMOVE
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	maintenance, err = client.UpdateMaintenance(maintenance, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating maintenance",
			Detail:   formatError(err),
		})
		return diags
	}

	setMaintenanceData(d, maintenance)

	return diags
}

// resourceMyrasecMaintenanceDelete
func resourceMyrasecMaintenanceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	maintenanceID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing maintenance ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting maintenance: %v", maintenanceID)

	maintenance, err := buildMaintenance(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building maintenance",
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

	_, err = client.DeleteMaintenance(maintenance, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting maintenance",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecMaintenanceImport
func resourceMyrasecMaintenanceImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	subDomainName, maintenanceID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing maintenance ID: [%s]", err.Error())
	}

	maintenance, diags := findMaintenance(maintenanceID, meta, subDomainName)
	if diags.HasError() || maintenance == nil {
		return nil, fmt.Errorf("unable to find maintenance for subdomain [%s] with ID = [%d]", subDomainName, maintenanceID)
	}

	d.SetId(strconv.Itoa(maintenanceID))
	d.Set("maintenance_id", maintenance.ID)
	d.Set("start", maintenance.Start)
	d.Set("end", maintenance.End)
	d.Set("content", maintenance.Content)
	d.Set("subdomain_name", maintenance.FQDN)

	resourceMyrasecMaintenanceRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildMaintenance
func buildMaintenance(d *schema.ResourceData, meta interface{}) (*myrasec.Maintenance, error) {
	maintenance := &myrasec.Maintenance{
		Content: d.Get("content").(string),
		FQDN:    d.Get("subdomain_name").(string),
	}

	if d.Get("maintenance_id").(int) > 0 {
		maintenance.ID = d.Get("maintenance_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			maintenance.ID = id
		}
	}

	start, err := types.ParseDate(d.Get("start").(string))
	if err != nil {
		return nil, err
	}
	maintenance.Start = start

	end, err := types.ParseDate(d.Get("end").(string))
	if err != nil {
		return nil, err
	}
	maintenance.End = end

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	maintenance.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	maintenance.Modified = modified

	return maintenance, nil
}

// findMaintenance
func findMaintenance(maintenanceID int, meta interface{}, subDomainName string) (*myrasec.Maintenance, diag.Diagnostics) {
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

	page := 1
	pageSize := 100
	params := map[string]string{
		"pageSize": strconv.Itoa(pageSize),
		"page":     strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListMaintenances(domain.ID, subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading maintenance",
				Detail:   formatError(err),
			})
			return nil, diags
		}

		for _, m := range res {
			if m.ID == maintenanceID {
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
		Summary:  "Unable to find maintenance",
		Detail:   fmt.Sprintf("Unable to find maintenance with ID = [%d]", maintenanceID),
	})
	return nil, diags
}

// setMaintenanceData ...
func setMaintenanceData(d *schema.ResourceData, maintenance *myrasec.Maintenance) {
	d.SetId(strconv.Itoa(maintenance.ID))
	d.Set("maintenance_id", maintenance.ID)
	d.Set("created", maintenance.Created.Format(time.RFC3339))
	d.Set("modified", maintenance.Modified.Format(time.RFC3339))
	d.Set("start", maintenance.Start.Format(time.RFC3339))
	d.Set("end", maintenance.End.Format(time.RFC3339))
	d.Set("content", maintenance.Content)
	d.Set("subdomain_name", maintenance.FQDN)
	d.Set("active", maintenance.Active)
}
