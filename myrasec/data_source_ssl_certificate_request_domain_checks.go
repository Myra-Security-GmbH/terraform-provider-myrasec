package myrasec

import (
	"context"
	"sort"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// dataSourceMyrasecSSLCertificateRequestDomainChecks ...
func dataSourceMyrasecSSLCertificateRequestDomainChecks() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecSSLCertificateRequestDomainChecksRead,
		Schema: map[string]*schema.Schema{
			"domains": {
				Type:        schema.TypeList,
				Required:    true,
				MinItems:    1,
				MaxItems:    99,
				Description: "Domains to check, e.g. www.example.com or *.example.org.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
					StateFunc: func(i any) string {
						return strings.ToLower(myrasec.RemoveTrailingDot(i.(string)))
					},
				},
			},
			"checks": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"exists": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"is_myra_ns": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"challenge_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"expected_cname": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// dataSourceMyrasecSSLCertificateRequestDomainChecksRead ...
func dataSourceMyrasecSSLCertificateRequestDomainChecksRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	domains := make([]string, 0)
	for _, domain := range d.Get("domains").([]any) {
		domains = append(domains, strings.ToLower(myrasec.RemoveTrailingDot(domain.(string))))
	}

	checks, err := client.CheckSSLCertificateRequestDomains(domains)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error checking domains for SSL certificate request",
			Detail:   formatError(err),
		})
		return diags
	}

	// Domains whose lookup failed are absent from the result. The result is sorted by
	// domain to keep the state stable between runs.
	names := make([]string, 0, len(checks))
	for name := range checks {
		names = append(names, name)
	}
	sort.Strings(names)

	checkData := make([]any, 0, len(names))
	for _, name := range names {
		check := checks[name]
		checkData = append(checkData, map[string]any{
			"domain":         name,
			"exists":         check.Exists,
			"is_myra_ns":     check.IsMyraNS,
			"challenge_name": check.ChallengeName,
			"expected_cname": check.ExpectedCName,
		})
	}

	if err := d.Set("checks", checkData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createContentHash(strings.Join(domains, ",")))

	return diags
}
