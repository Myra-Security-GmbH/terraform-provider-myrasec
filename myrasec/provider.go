package myrasec

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// Provider retruns a terraform.ResourceProvider.
//
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
				Default:     "https://api.myracloud.com/%s/rapi/%s",
				Description: "API Base URL. Keep the default value. No change required.",
			},
		},
		DataSourcesMap: map[string]*schema.Resource{
			"myrasec_domains":        dataSourceMyrasecDomains(),
			"myrasec_dns_records":    dataSourceMyrasecDNSRecords(),
			"myrasec_cache_settings": dataSourceMyrasecCacheSettings(),
			"myrasec_redirects":      dataSourceMyrasecRedirects(),
			"myrasec_ratelimits":     dataSourceMyrasecRateLimits(),
			"myrasec_waf_conditions": dataSourceMyrasecWAFConditions(),
			"myrasec_waf_actions":    dataSourceMyrasecWAFActions(),
		},
		ResourcesMap: map[string]*schema.Resource{
			"myrasec_domain":        resourceMyrasecDomain(),
			"myrasec_dns_record":    resourceMyrasecDNSRecord(),
			"myrasec_cache_setting": resourceMyrasecCacheSetting(),
			"myrasec_redirect":      resourceMyrasecRedirect(),
			"myrasec_settings":      resourceMyrasecSettings(),
			"myrasec_ip_filter":     resourceMyrasecIPFilter(),
			"myrasec_ratelimit":     resourceMyrasecRateLimit(),
			"myrasec_waf_rule":      resourceMyrasecWAFRule(),
		},
		ConfigureFunc: providerConfigure,
	}
}

//
// providerConfigure ...
//
func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		APIKey:     d.Get("api_key").(string),
		Secret:     d.Get("secret").(string),
		Language:   d.Get("language").(string),
		APIBaseURL: d.Get("api_base_url").(string),
	}

	if err := config.validate(); err != nil {
		return nil, err
	}

	client, err := config.Client()
	if err != nil {
		return nil, err
	}

	return client, nil
}
