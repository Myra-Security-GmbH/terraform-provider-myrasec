package myrasec

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider retruns a terraform.ResourceProvider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYRASEC_API_KEY", nil),
				Description: "Your MYRA API Key",
			},
			"secret": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYRASEC_API_SECRET", nil),
				Description: "Your MYRA API Secret",
			},
			"language": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "en",
				Description: "The API language",
			},
			"api_base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYRASEC_API_BASE_URL", "https://apiv2.myracloud.com/%s"),
				Description: "API Base URL. Keep the default value. No change required.",
			},
			"api_cache_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYRASEC_API_CACHE_TTL", 30),
				Description: "API Cache TTL. Keep the default value. No change required.",
			},
		},
		DataSourcesMap: map[string]*schema.Resource{
			"myrasec_domains":               dataSourceMyrasecDomains(),
			"myrasec_dns_records":           dataSourceMyrasecDNSRecords(),
			"myrasec_cache_settings":        dataSourceMyrasecCacheSettings(),
			"myrasec_redirects":             dataSourceMyrasecRedirects(),
			"myrasec_settings":              dataSourceMyrasecSettings(),
			"myrasec_ip_filters":            dataSourceMyrasecIPFilters(),
			"myrasec_waf_rules":             dataSourceMyrasecWAFRules(),
			"myrasec_waf_conditions":        dataSourceMyrasecWAFConditions(),
			"myrasec_waf_actions":           dataSourceMyrasecWAFActions(),
			"myrasec_ip_ranges":             dataSourceMyrasecIPRanges(),
			"myrasec_ssl_certificates":      dataSourceMyrasecSSLCertificates(),
			"myrasec_ssl_configurations":    dataSourceMyrasecSSLConfigurations(),
			"myrasec_error_pages":           dataSourceMyrasecErrorPages(),
			"myrasec_maintenances":          dataSourceMyrasecMaintenances(),
			"myrasec_maintenance_templates": dataSourceMyrasecMaintenanceTemplates(),
			"myrasec_tags":                  dataSourceMyrasecTags(),
			"myrasec_tag_cache_settings":    dataSourceMyrasecTagCacheSettings(),
			"myrasec_tag_information":       dataSourceMyrasecTagInformation(),
			"myrasec_tag_settings":          dataSourceMyrasecTagSettings(),
			"myrasec_tag_waf_rules":         dataSourceMyrasecTagWAFRules(),
			"myrasec_waitingrooms":          dataSourceMyrasecWaitingRooms(),
		},
		ResourcesMap: map[string]*schema.Resource{
			"myrasec_domain":               resourceMyrasecDomain(),
			"myrasec_dns_record":           resourceMyrasecDNSRecord(),
			"myrasec_cache_setting":        resourceMyrasecCacheSetting(),
			"myrasec_redirect":             resourceMyrasecRedirect(),
			"myrasec_settings":             resourceMyrasecSettings(),
			"myrasec_ip_filter":            resourceMyrasecIPFilter(),
			"myrasec_waf_rule":             resourceMyrasecWAFRule(),
			"myrasec_ssl_certificate":      resourceMyrasecSSLCertificate(),
			"myrasec_error_page":           resourceMyrasecErrorPage(),
			"myrasec_maintenance":          resourceMyrasecMaintenance(),
			"myrasec_maintenance_template": resourceMyrasecMaintenanceTemplate(),
			"myrasec_tag":                  resourceMyrasecTag(),
			"myrasec_tag_cache_setting":    resourceMyrasecTagCacheSetting(),
			"myrasec_tag_information":      resourceMyrasecTagInformation(),
			"myrasec_tag_waf_rule":         resourceMyrasecTagWAFRule(),
			"myrasec_tag_settings":         resourceMyrasecTagSettings(),
			"myrasec_waitingroom":          resourceMyrasecWaitingRoom(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

// providerConfigure ...
func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	config := Config{
		APIKey:        d.Get("api_key").(string),
		Secret:        d.Get("secret").(string),
		Language:      d.Get("language").(string),
		APIBaseURL:    d.Get("api_base_url").(string),
		APICacheTTL:   d.Get("api_cache_ttl").(int),
		APIRetryCount: 3,
		APIRetrySleep: 1,
	}

	var diags diag.Diagnostics

	if err := config.validate(); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Configuration not valid",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	client, err := config.Client()
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to create API client",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	return client, diags
}
