package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// dataSourceMyrasecSSLProviderCertificates ...
func dataSourceMyrasecSSLProviderCertificates() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecSSLProviderCertificatesRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"credentials_id": {
							Type:        schema.TypeInt,
							Required:    true,
							Description: "ID of the SSL provider credentials the certificates were issued with.",
						},
						"search": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"certificates": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"modified": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"subject": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"subject_alternatives": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"algorithm": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"valid_from": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"valid_to": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"fingerprint": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"serial_number": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"wildcard": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"extended_validation": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"managed": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"multidomain": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"configuration_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"request_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"domain_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"subdomains": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
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

// dataSourceMyrasecSSLProviderCertificatesRead ...
func dataSourceMyrasecSSLProviderCertificatesRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	f := prepareSSLProviderCertificatesFilter(d.Get("filter"))
	if f == nil {
		f = &sslProviderCertificatesFilter{}
	}

	params := map[string]string{}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	certificates, diags := listSSLProviderCertificates(meta, f.credentialsID, params)
	if diags.HasError() {
		return diags
	}

	certificateData := make([]any, 0, len(certificates))
	for _, c := range certificates {
		certificateData = append(certificateData, map[string]any{
			"id":                   c.ID,
			"created":              formatDateTime(c.Created),
			"modified":             formatDateTime(c.Modified),
			"subject":              c.Subject,
			"subject_alternatives": c.SubjectAlternatives,
			"algorithm":            c.Algorithm,
			"valid_from":           formatDateTime(c.ValidFrom),
			"valid_to":             formatDateTime(c.ValidTo),
			"fingerprint":          c.Fingerprint,
			"serial_number":        c.SerialNumber,
			"wildcard":             c.Wildcard,
			"extended_validation":  c.ExtendedValidation,
			"managed":              c.Managed,
			"multidomain":          c.Multidomain,
			"configuration_name":   c.SslConfigurationName,
			"request_id":           c.RequestID,
			"domain_id":            c.DomainID,
			"subdomains":           c.Subdomains,
		})
	}

	if err := d.Set("certificates", certificateData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

// prepareSSLProviderCertificatesFilter fetches the panic that can happen in parseSSLProviderCertificatesFilter
func prepareSSLProviderCertificatesFilter(d any) *sslProviderCertificatesFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareSSLProviderCertificatesFilter", r)
		}
	}()

	return parseSSLProviderCertificatesFilter(d)
}

// parseSSLProviderCertificatesFilter converts the filter data to a sslProviderCertificatesFilter struct
func parseSSLProviderCertificatesFilter(d any) *sslProviderCertificatesFilter {
	cfg := d.([]any)
	f := &sslProviderCertificatesFilter{}

	m := cfg[0].(map[string]any)

	credentialsID, ok := m["credentials_id"]
	if ok {
		f.credentialsID = credentialsID.(int)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	return f
}

// listSSLProviderCertificates ...
func listSSLProviderCertificates(meta any, credentialsID int, params map[string]string) ([]myrasec.SSLCertificateSummary, diag.Diagnostics) {
	var diags diag.Diagnostics
	var certificates []myrasec.SSLCertificateSummary
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListSSLProviderCertificates(credentialsID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching SSL provider certificates",
				Detail:   formatError(err),
			})
			return certificates, diags
		}
		certificates = append(certificates, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return certificates, diags
}

// sslProviderCertificatesFilter ...
type sslProviderCertificatesFilter struct {
	credentialsID int
	search        string
}
