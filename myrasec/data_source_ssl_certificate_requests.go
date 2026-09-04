package myrasec

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// sslCertificateRequestStatuses lists every status of a managed certificate request
var sslCertificateRequestStatuses = []string{
	myrasec.SSLCertificateRequestStatusOpen,
	myrasec.SSLCertificateRequestStatusWaitingForCNAME,
	myrasec.SSLCertificateRequestStatusCreated,
	myrasec.SSLCertificateRequestStatusFailed,
}

// dataSourceMyrasecSSLCertificateRequests ...
func dataSourceMyrasecSSLCertificateRequests() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecSSLCertificateRequestsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain_name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Restrict the result to requests of one domain.",
						},
						"status": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Statuses to include: OPEN, WAITING_FOR_CNAME, CREATED, FAILED. Defaults to all statuses.",
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.StringInSlice(sslCertificateRequestStatuses, false),
							},
						},
						"search": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Restrict the result to requests with an assigned subdomain whose name contains the search string.",
						},
					},
				},
			},
			"requests": {
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
						"certificate_provider": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"algorithm": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"status": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"failure_reason": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"customer_actionable": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"multi_domain": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"subject_alternative_names": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"subdomains": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"ssl_provider_credentials_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"renewal_interval": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"signature_algorithm": {
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

// dataSourceMyrasecSSLCertificateRequestsRead ...
func dataSourceMyrasecSSLCertificateRequestsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	f := prepareSSLCertificateRequestFilter(d.Get("filter"))
	if f == nil {
		f = &sslCertificateRequestFilter{}
	}

	// Without a status parameter the API omits requests whose certificate has been issued.
	statuses := f.statuses
	if len(statuses) == 0 {
		statuses = sslCertificateRequestStatuses
	}

	params := map[string]string{
		"status": strings.Join(statuses, ","),
	}
	if len(f.domainName) > 0 {
		params["domain"] = f.domainName
	}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	requests, diags := listSSLCertificateRequests(meta, params)
	if diags.HasError() {
		return diags
	}

	requestData := make([]any, 0, len(requests))
	for _, r := range requests {
		names := make([]string, 0, len(r.SubjectAlternativeNames))
		for _, san := range r.SubjectAlternativeNames {
			names = append(names, san.Name)
		}

		subdomains := make([]string, 0, len(r.Assignments))
		for _, assignment := range r.Assignments {
			subdomains = append(subdomains, assignment.SubDomainName)
		}

		requestData = append(requestData, map[string]any{
			"id":                          r.ID,
			"created":                     formatDateTime(r.Created),
			"modified":                    formatDateTime(r.Modified),
			"certificate_provider":        r.Provider,
			"algorithm":                   r.Algorithm,
			"status":                      r.Status,
			"failure_reason":              r.FailureReason,
			"customer_actionable":         r.CustomerActionable,
			"multi_domain":                r.MultiDomain,
			"subject_alternative_names":   names,
			"subdomains":                  subdomains,
			"ssl_provider_credentials_id": r.SSLProviderCredentialsID,
			"renewal_interval":            r.RenewalInterval,
			"signature_algorithm":         r.SignatureAlgorithm,
		})
	}

	if err := d.Set("requests", requestData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

// prepareSSLCertificateRequestFilter fetches the panic that can happen in parseSSLCertificateRequestFilter
func prepareSSLCertificateRequestFilter(d any) *sslCertificateRequestFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareSSLCertificateRequestFilter", r)
		}
	}()

	return parseSSLCertificateRequestFilter(d)
}

// parseSSLCertificateRequestFilter converts the filter data to a sslCertificateRequestFilter struct
func parseSSLCertificateRequestFilter(d any) *sslCertificateRequestFilter {
	cfg := d.([]any)
	f := &sslCertificateRequestFilter{}

	m := cfg[0].(map[string]any)

	domainName, ok := m["domain_name"]
	if ok {
		f.domainName = domainName.(string)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	statuses, ok := m["status"]
	if ok {
		for _, s := range statuses.([]any) {
			f.statuses = append(f.statuses, s.(string))
		}
	}

	return f
}

// listSSLCertificateRequests ...
func listSSLCertificateRequests(meta any, params map[string]string) ([]myrasec.SSLCertificateRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	var requests []myrasec.SSLCertificateRequest
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListSSLCertificateRequests(params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching SSL certificate requests",
				Detail:   formatError(err),
			})
			return requests, diags
		}
		requests = append(requests, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return requests, diags
}

// sslCertificateRequestFilter ...
type sslCertificateRequestFilter struct {
	domainName string
	search     string
	statuses   []string
}
