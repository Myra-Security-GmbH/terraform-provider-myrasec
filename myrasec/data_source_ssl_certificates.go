package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
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
		certificateData = append(certificateData, map[string]interface{}{
			"id":       c.ID,
			"created":  c.Created.Format(time.RFC3339),
			"modified": c.Modified.Format(time.RFC3339),
			// @TODO - define schema
		})
	}

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

	client := meta.(*myrasec.API)

	params["pageSize"] = "50"
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListSSLCertificates(domainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching SSL certificates",
				Detail:   err.Error(),
			})
			return certificates, diags
		}
		certificates = append(certificates, res...)
		if len(res) < 50 {
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
