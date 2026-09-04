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

// dataSourceMyrasecSSLProviderCredentials ...
func dataSourceMyrasecSSLProviderCredentials() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecSSLProviderCredentialsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"certificate_provider": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Restrict the result to one provider: SECTIGO or DTRUST.",
						},
						"search": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Restrict the result to credentials whose name, email or EAB key identifier contains the search string.",
						},
					},
				},
			},
			"credentials": {
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
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"certificate_provider": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"cert": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"email": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"endpoint": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"eab_kid": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"comment": {
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

// dataSourceMyrasecSSLProviderCredentialsRead ...
func dataSourceMyrasecSSLProviderCredentialsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	f := prepareSSLProviderCredentialsFilter(d.Get("filter"))
	if f == nil {
		f = &sslProviderCredentialsFilter{}
	}

	params := map[string]string{}
	if len(f.provider) > 0 {
		params["provider"] = f.provider
	}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	credentials, diags := listSSLProviderCredentials(meta, params)
	if diags.HasError() {
		return diags
	}

	credentialsData := make([]any, 0, len(credentials))
	for _, c := range credentials {
		credentialsData = append(credentialsData, map[string]any{
			"id":                   c.ID,
			"created":              formatDateTime(c.Created),
			"modified":             formatDateTime(c.Modified),
			"name":                 c.Name,
			"certificate_provider": c.Provider,
			"cert":                 c.Cert,
			"email":                c.Email,
			"endpoint":             c.Endpoint,
			"eab_kid":              c.EABKid,
			"comment":              c.Comment,
		})
	}

	if err := d.Set("credentials", credentialsData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

// prepareSSLProviderCredentialsFilter fetches the panic that can happen in parseSSLProviderCredentialsFilter
func prepareSSLProviderCredentialsFilter(d any) *sslProviderCredentialsFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareSSLProviderCredentialsFilter", r)
		}
	}()

	return parseSSLProviderCredentialsFilter(d)
}

// parseSSLProviderCredentialsFilter converts the filter data to a sslProviderCredentialsFilter struct
func parseSSLProviderCredentialsFilter(d any) *sslProviderCredentialsFilter {
	cfg := d.([]any)
	f := &sslProviderCredentialsFilter{}

	m := cfg[0].(map[string]any)

	provider, ok := m["certificate_provider"]
	if ok {
		f.provider = provider.(string)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	return f
}

// listSSLProviderCredentials ...
func listSSLProviderCredentials(meta any, params map[string]string) ([]myrasec.SSLProviderCredentials, diag.Diagnostics) {
	var diags diag.Diagnostics
	var credentials []myrasec.SSLProviderCredentials
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListSSLProviderCredentials(params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching SSL provider credentials",
				Detail:   formatError(err),
			})
			return credentials, diags
		}
		credentials = append(credentials, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return credentials, diags
}

// sslProviderCredentialsFilter ...
type sslProviderCredentialsFilter struct {
	provider string
	search   string
}
