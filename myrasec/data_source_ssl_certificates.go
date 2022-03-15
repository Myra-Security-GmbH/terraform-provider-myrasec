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

//
// dataSourceMyrasecSSLCertificates ...
//
func dataSourceMyrasecSSLCertificates() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecSSLCertificatesRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain_name": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"certificates": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"modified": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"subject": {
							Type:     schema.TypeString,
							Computed: true,
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
						"subject_alternatives": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"wildcard": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"extended_validation": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"subdomains": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"intermediates": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"subject": {
										Type:     schema.TypeString,
										Computed: true,
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
									"issuer": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
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

//
// dataSourceMyrasecSSLCertificatesRead ...
//
func dataSourceMyrasecSSLCertificatesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareSSLCertificateFilter(d.Get("filter"))
	if f == nil {
		f = &sslCertificateFilter{}
	}

	params := map[string]string{}

	certificates, diags := listSSLCertificates(meta, f.domainName, params)
	if diags.HasError() {
		return diags
	}

	certificateData := make([]interface{}, 0)

	for _, c := range certificates {

		var created string
		if c.Created != nil {
			created = c.Certificate.Created.Format(time.RFC3339)
		}

		var modified string
		if c.Created != nil {
			modified = c.Certificate.Modified.Format(time.RFC3339)
		}
		data := map[string]interface{}{
			"domain_name":          f.domainName,
			"id":                   c.Certificate.ID,
			"created":              created,
			"modified":             modified,
			"subject":              c.Certificate.Subject,
			"algorithm":            c.Certificate.Algorithm,
			"valid_from":           c.Certificate.ValidFrom.Format(time.RFC3339),
			"valid_to":             c.Certificate.ValidTo.Format(time.RFC3339),
			"fingerprint":          c.Certificate.Fingerprint,
			"serial_number":        c.Certificate.SerialNumber,
			"subject_alternatives": c.SubjectAlternatives,
			"wildcard":             c.Wildcard,
			"extended_validation":  c.ExtendedValidation,
			"subdomains":           c.Subdomains,
		}

		if c.Intermediates != nil && len(c.Intermediates) > 0 {
			intermediates := make([]map[string]interface{}, 0)
			for _, inter := range c.Intermediates {
				intermediates = append(intermediates, map[string]interface{}{
					"subject":       inter.Certificate.Subject,
					"algorithm":     inter.Certificate.Algorithm,
					"fingerprint":   inter.Certificate.Fingerprint,
					"serial_number": inter.Certificate.SerialNumber,
					"valid_from":    inter.Certificate.ValidFrom.Format(time.RFC3339),
					"valid_to":      inter.Certificate.ValidTo.Format(time.RFC3339),
					"issuer":        inter.Issuer,
				})
			}
			data["intermediates"] = intermediates
		}

		certificateData = append(certificateData, data)
	}

	if err := d.Set("certificates", certificateData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

//
// prepareSSLCertificateFilter fetches the panic that can happen in parseSSLCertificateFilter
//
func prepareSSLCertificateFilter(d interface{}) *sslCertificateFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareRedirectFilter", r)
		}
	}()

	return parseSSLCertificateFilter(d)
}

//
// parseSSLCertificateFilter converts the filter data to a sslCertificateFilter struct
//
func parseSSLCertificateFilter(d interface{}) *sslCertificateFilter {
	cfg := d.([]interface{})
	f := &sslCertificateFilter{}

	m := cfg[0].(map[string]interface{})

	domainName, ok := m["domain_name"]
	if ok {
		f.domainName = domainName.(string)
	}

	return f
}

//
// listSSLCertificates ...
//
func listSSLCertificates(meta interface{}, domainName string, params map[string]string) ([]myrasec.SSLCertificate, diag.Diagnostics) {
	var diags diag.Diagnostics
	var certificates []myrasec.SSLCertificate
	pageSize := 250

	client := meta.(*myrasec.API)

	domain, err := fetchDomain(client, domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   err.Error(),
		})
		return certificates, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListSSLCertificates(domain.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching SSL certificates",
				Detail:   err.Error(),
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

//
// sslCertificateFilter ...
//
type sslCertificateFilter struct {
	domainName string
}
