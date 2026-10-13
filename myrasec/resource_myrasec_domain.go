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

// resourceMyrasecDomain ...
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
				StateFunc: func(i any) string {
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
			"verified": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether domain ownership is verified. Unverified domains are not published. Defaults to true if the API does not return verification status.",
			},
			"paused": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Shows if Myra is paused for this domain.",
				Deprecated:  "Attribute `paused` is deprecated and has no effect anymore",
			},
			"paused_until": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Date until Myra will be automatically reactivated.",
				Deprecated:  "Attribute `paused_until` is deprecated and has no effect anymore",
			},
		},
		CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, i any) error {
			currentDomainName, newDomainName := d.GetChange("name")
			if currentDomainName != "" && currentDomainName != newDomainName {
				return fmt.Errorf("it's not allowed to change domain name")
			}

			return nil
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecDomainCreate ...
func resourceMyrasecDomainCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	domain, err := buildDomain(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building domain",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.CreateDomain(domain)
	if err != nil {
		var errImport error
		resp, errImport = importExistingDomain(domain, meta)
		if errImport != nil {
			log.Printf("[DEBUG] auto-import failed: %s", errImport)
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error creating domain",
				Detail:   formatError(fmt.Errorf("%w\nAutomatic import also failed: %v", err, errImport)),
			})

			return diags
		}
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	diags = resourceMyrasecDomainRead(ctx, d, meta)
	if diags.HasError() {
		d.Set("verified", !resp.IsPendingVerification())
		diags = append(diags, domainVerificationDiagnostics(resp)...)
	}
	return diags

}

// resourceMyrasecDomainRead ...
func resourceMyrasecDomainRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics

	domainID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing domain ID",
			Detail:   formatError(err),
		})
		return diags
	}

	domain, diags := findDomain(domainID, meta)
	if diags.HasError() {
		return diags
	}

	if domain == nil {
		d.SetId("")
		return nil
	}

	setDomainData(d, domain)

	return append(diags, domainVerificationDiagnostics(domain)...)
}

// resourceMyrasecDomainUpdate ...
func resourceMyrasecDomainUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	domain, err := buildDomain(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building domain",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.UpdateDomain(domain)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating domain",
			Detail:   formatError(err),
		})
		return diags
	}

	setDomainData(d, resp)

	return append(diags, domainVerificationDiagnostics(resp)...)
}

// resourceMyrasecDomainDelete ...
func resourceMyrasecDomainDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	domainID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing domain ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting Domain: %v", domainID)

	domain, err := buildDomain(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building domain",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.DeleteDomain(domain)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting domain",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecDomainImport ...
func resourceMyrasecDomainImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {

	var domain *myrasec.Domain
	var diags diag.Diagnostics
	var err error

	domainID, err := strconv.Atoi(d.Id())
	if err == nil {
		domain, diags = findDomain(domainID, meta)
		if diags.HasError() || domain == nil {
			return nil, fmt.Errorf("unable to find domain with ID = [%d]", domainID)
		}
	} else {
		client := meta.(*myrasec.API)
		domain, err = client.FetchDomain(d.Id())
		if err != nil {
			return nil, err
		}
	}

	// Terraform refreshes the imported state through ReadContext, which emits diagnostics.
	d.SetId(strconv.Itoa(domain.ID))
	d.Set("domain_id", domain.ID)

	return []*schema.ResourceData{d}, nil
}

// buildDomain ...
func buildDomain(d *schema.ResourceData) (*myrasec.Domain, error) {
	domain := &myrasec.Domain{
		Name:       d.Get("name").(string),
		AutoUpdate: d.Get("auto_update").(bool),
		AutoDNS:    false,
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

	return domain, nil
}

// findDomain ...
func findDomain(domainID int, meta any) (*myrasec.Domain, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	d, err := client.GetDomain(domainID)
	if err != nil {
		if isNotFoundError(err) {
			return nil, nil
		}
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error loading domain",
			Detail:   formatError(err),
		})
		return nil, diags
	}
	if d != nil {
		return d, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find domain",
		Detail:   fmt.Sprintf("Unable to find domain with ID = [%d]", domainID),
	})
	return nil, diags
}

func domainVerificationDiagnostics(domain *myrasec.Domain) diag.Diagnostics {
	if !domain.IsPendingVerification() {
		return nil
	}
	return diag.Diagnostics{{
		Severity: diag.Warning,
		Summary:  "Domain ownership verification pending or revoked",
		Detail:   fmt.Sprintf("Domain %q is stored but is not published because its ownership verification is pending or has been revoked. Open the Myra dashboard to view the verification status and follow the instructions there. Terraform does not manage domain verification.", domain.Name),
	}}
}

// setDomainData ...
func setDomainData(d *schema.ResourceData, domain *myrasec.Domain) {
	d.SetId(fmt.Sprintf("%d", domain.ID))
	d.Set("domain_id", domain.ID)
	d.Set("name", domain.Name)
	d.Set("auto_update", domain.AutoUpdate)
	d.Set("verified", !domain.IsPendingVerification())
	d.Set("created", domain.Created.Format(time.RFC3339))
	d.Set("modified", domain.Modified.Format(time.RFC3339))
}

// importExistingDomain ...
func importExistingDomain(domain *myrasec.Domain, meta any) (*myrasec.Domain, error) {
	client := meta.(*myrasec.API)

	params := map[string]string{
		"search": domain.Name,
	}

	domains, err := client.ListDomains(params)
	if err != nil {
		return nil, err
	}

	if len(domains) <= 0 {
		return nil, fmt.Errorf("unable to find existing domain for automatic import")
	}

	for _, d := range domains {
		if d.Name != domain.Name {
			continue
		}

		return &d, nil
	}

	return nil, fmt.Errorf("unable to find existing domain for automatic import")
}
