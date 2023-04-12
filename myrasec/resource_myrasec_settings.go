package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const (
	defaultValueAccessLog                   = true
	defaultValueAntibotPostFlood            = false
	defaultValueAntibotPostFloodThreshold   = 540
	defaultValueAntibotProofOfWork          = true
	defaultValueAntibotProofOfWorkThreshold = 1800
	defaultValueBalancingMethod             = "round_robin"
	defaultValueBlockNotWhitelisted         = false
	defaultValueBlockTorNetwork             = false
	defaultValueCacheEnabled                = false
	defaultValueCacheRevalidate             = false
	defaultValueCDN                         = false
	defaultValueClientMaxBodySize           = 10
	defaultValueDiffieHellmanExchange       = 2048
	defaultValueEnableOriginSNI             = true
	defaultValueForwardedForReplacement     = "X-Forwarded-For"
	defaultValueHSTS                        = false
	defaultValueHSTSIncludeSubdomains       = false
	defaultValueHSTSMaxAge                  = 31536000
	defaultValueHSTSPreload                 = false
	defaultValueHTTPOriginPort              = 80
	defaultValueIgnoreNoCache               = false
	defaultValueImageOptimization           = true
	defaultValueIPv6Active                  = true
	defaultValueLogFormat                   = "myra-combined-waf"
	defaultValueMonitoringAlertThreshold    = 300
	defaultValueMonitoringContactEMail      = ""
	defaultValueMonitoringSendAlert         = false
	defaultValueMyraSSLHeader               = false
	defaultValueOnlyHTTPS                   = false
	defaultValueOriginConnectionHeader      = "none"
	defaultValueProxyCacheBypass            = ""
	defaultValueProxyConnectTimeout         = 60
	defaultValueProxyReadTimeout            = 600
	defaultValueRequestLimitBlock           = "CAPTCHA"
	defaultValueRequestLimitLevel           = 6000
	defaultValueRequestLimitReport          = false
	defaultValueRequestLimitReportEMail     = ""
	defaultValueRewrite                     = false
	defaultValueSourceProtocol              = "same"
	defaultValueSpdy                        = true
	defaultValueSSLOriginPort               = 443
	defaultValueWAFEnable                   = false
	defaultValueWAFPolicy                   = "allow"
)

// resourceMyrasecSettings ...
func resourceMyrasecSettings() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecSettingsCreate,
		ReadContext:   resourceMyrasecSettingsRead,
		UpdateContext: resourceMyrasecSettingsUpdate,
		DeleteContext: resourceMyrasecSettingsDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					name := i.(string)
					if myrasec.IsGeneralDomainName(name) {
						return name
					}
					return strings.ToLower(name)
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new)
				},
				Description: "The Subdomain for the Settings.",
			},
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Stores domain Id for subdomain.",
			},
			"access_log": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Activate separated access log",
			},
			"antibot_post_flood": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Detection of POST floods by using a JavaScript based puzzle.",
			},
			"antibot_post_flood_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved.",
			},
			"antibot_proof_of_work": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Detection of valid clients by using a JavaScript based puzzle.",
			},
			"antibot_proof_of_work_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved.",
			},
			"balancing_method": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"round_robin", "ip_hash", "least_conn"}, false),
				Description:  "Specifies with which method requests are balanced between upstream servers.",
			},
			"block_not_whitelisted": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Block all IPs, which are not whitelisted.",
			},
			"block_tor_network": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Block traffic from the TOR network.",
			},
			"cache_enabled": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Turn caching on or off.",
			},
			"cache_revalidate": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable stale cache item revalidation.",
			},
			"cdn": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Use subdomain as Content Delivery Node (CDN).",
			},
			"client_max_body_size": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Sets the maximum allowed size of the client request body, specified in the “Content-Length” request header field. Maximum 100MB.",
			},
			"diffie_hellman_exchange": {
				Type:         schema.TypeInt,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.IntInSlice([]int{1024, 2048}),
				Description:  "The Diffie-Hellman key exchange parameter length.",
			},
			"enable_origin_sni": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable or disable origin SNI.",
			},
			"forwarded_for_replacement": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Set your own X-Forwarded-For header.",
			},
			"hsts": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "HSTS Strict Transport Security (HSTS).",
			},
			"hsts_include_subdomains": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "HSTS includeSubDomains directive.",
			},
			"hsts_max_age": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "HSTS max-age.",
			},
			"hsts_preload": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "HSTS preload directive.",
			},
			"http_origin_port": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Allows to set a port for communication with origin via HTTP.",
			},
			"ignore_nocache": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If activated, no-cache headers (Cache-Control: [private|no-store|no-cache]) will be ignored.",
			},
			"image_optimization": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Optimization of images.",
			},
			"ipv6_active": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Allow connections via IPv6 to your systems.",
			},
			"limit_allowed_http_method": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Not selected HTTP methods will be blocked.",
			},
			"limit_tls_version": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Only selected TLS versions will be used.",
			},
			"log_format": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Use a different log format.",
			},
			"monitoring_alert_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Errors per minute that must occur until a report is sent.",
			},
			"monitoring_contact_email": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Email addresses, to which monitoring emails should be send. Multiple addresses are separated with a space.",
			},
			"monitoring_send_alert": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enables / disables the upstream error reporting.",
			},
			"myra_ssl_header": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Activates the X-Myra-SSL Header.",
			},
			"next_upstream": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the error that mark the current upstream as \"down\".",
			},
			"only_https": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Shall the origin server always be requested via HTTPS?",
			},
			"origin_connection_header": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"none", "close", "upgrade"}, false),
				Description:  "Connection header.",
			},
			"proxy_cache_bypass": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of the cookie which forces Myra to deliver the response not from cache.",
			},
			"proxy_cache_stale": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Determines in which cases a stale cached response can be used when an error occurs.",
			},
			"proxy_connect_timeout": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Timeout for establishing a connection to the upstream server.",
			},
			"proxy_read_timeout": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Timeout for reading the upstream response.",
			},
			"request_limit_block": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"CAPTCHA", "HTTP429", "no"}, false),
				Description:  "Show CAPTCHA after exceeding the configured request limit.",
			},
			"request_limit_level": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Sets how many requests are allowed from an IP per minute.",
			},
			"request_limit_report": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If activated, an email will be send containing blocked ip addresses that exceeded the configured request limit.",
			},
			"request_limit_report_email": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Email addresses, to which request limit emails should be send. Multiple addresses are separated with a space.",
			},
			"rewrite": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable the JavaScript optimization.",
			},
			"source_protocol": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"same", "http", "https"}, false),
				Description:  "Protocol to query the origin server.",
			},
			"spdy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Activates the SPDY protocol.",
			},
			"ssl_origin_port": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Allows to set a port for communication with origin via SSL.",
			},
			"waf_enable": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enables / disables the Web Application Firewall.",
			},
			"waf_levels_enable": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Level of applied WAF rules.",
			},
			"waf_policy": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"allow", "block"}, false),
				Description:  "Default policy for the Web Application Firewall in case of rule error.",
			},
			"proxy_host_header": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Proxy host header",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old == "$myra_host" && new == ""
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecSettingsCreate ...
func resourceMyrasecSettingsCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settings, err := buildSettings(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building settings",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	_, err = client.UpdateSettingsPartial(settings, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating settings",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return resourceMyrasecSettingsRead(ctx, d, meta)
}

// resourceMyrasecSettingsRead ...
func resourceMyrasecSettingsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics
	var subDomainName string

	name, ok := d.GetOk("subdomain_name")
	if ok {
		subDomainName = name.(string)
	} else {
		subDomainName = d.Id()
		d.Set("subdomain_name", subDomainName)
	}

	if len(subDomainName) < 4 {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing subdomain name",
			Detail:   formatError(fmt.Errorf("[%s] is not a valid subdomain name", subDomainName)),
		})
		return diags
	}

	domainID, diags := findDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	settings, err := client.ListSettings(domainID, subDomainName, nil)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching settings",
			Detail:   formatError(err),
		})
		return diags
	}

	setSettingsData(d, settings, subDomainName, domainID)

	return diags
}

// resourceMyrasecSettingsUpdate ...
func resourceMyrasecSettingsUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settings, err := buildSettings(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building settings",
			Detail:   formatError(err),
		})
		return diags
	}
	log.Printf("[INFO] Updating settings")

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	_, err = client.UpdateSettingsPartial(settings, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating settings",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	setSettingsDataByMap(d, settings, subDomainName, domainID)

	return diags
}

// resourceMyrasecSettingsDelete restores the default setting values
func resourceMyrasecSettingsDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting settings: %v", settingID)

	settings := make(map[string]interface{})

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	_, err = client.UpdateSettingsPartial(settings, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting settings",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// buildSettings ...
func buildSettings(d *schema.ResourceData, meta interface{}) (map[string]interface{}, error) {
	settingsMap := make(map[string]interface{})
	attributeMap := map[string]string{
		"access_log":                      "bool",
		"antibot_post_flood":              "bool",
		"antibot_post_flood_threshold":    "int",
		"antibot_proof_of_work":           "bool",
		"antibot_proof_of_work_threshold": "int",
		"balancing_method":                "string",
		"block_not_whitelisted":           "bool",
		"block_tor_network":               "bool",
		"cache_enabled":                   "bool",
		"cache_revalidate":                "bool",
		"cdn":                             "bool",
		"client_max_body_size":            "int",
		"diffie_hellman_exchange":         "int",
		"enable_origin_sni":               "bool",
		"forwarded_for_replacement":       "string",
		"hsts":                            "bool",
		"hsts_include_subdomains":         "bool",
		"hsts_max_age":                    "int",
		"hsts_preload":                    "bool",
		"http_origin_port":                "int",
		"ignore_nocache":                  "bool",
		"image_optimization":              "bool",
		"ipv6_active":                     "bool",
		"log_format":                      "string",
		"monitoring_alert_threshold":      "int",
		"monitoring_contact_email":        "string",
		"monitoring_send_alert":           "bool",
		"myra_ssl_header":                 "bool",
		"only_https":                      "bool",
		"origin_connection_header":        "string",
		"proxy_cache_bypass":              "string",
		"proxy_connect_timeout":           "int",
		"proxy_read_timeout":              "int",
		"request_limit_block":             "string",
		"request_limit_level":             "int",
		"request_limit_report":            "bool",
		"request_limit_report_email":      "string",
		"rewrite":                         "bool",
		"source_protocol":                 "string",
		"spdy":                            "bool",
		"ssl_origin_port":                 "int",
		"waf_enable":                      "bool",
		"waf_policy":                      "string",
	}

	for k, t := range attributeMap {
		value, ok := d.GetOk(k)
		if ok {
			switch t {
			case "bool":
				settingsMap[k] = value.(bool)
			case "int":
				settingsMap[k] = value.(int)
			case "string":
				settingsMap[k] = value.(string)
			}
		} else {
			settingsMap[k] = nil
		}
	}
	hostHeader := d.Get("proxy_host_header").(string)
	if hostHeader == "" {
		settingsMap["host_header"] = nil
	} else {
		settingsMap["host_header"] = &hostHeader
	}

	limitAllowedHttpMethodList, ok := d.GetOk("limit_allowed_http_method")
	if ok {
		limitAllowedHttpMethod := []string{}
		for _, method := range limitAllowedHttpMethodList.([]interface{}) {
			limitAllowedHttpMethod = append(limitAllowedHttpMethod, method.(string))
		}
		settingsMap["limit_allowed_http_method"] = limitAllowedHttpMethod
	} else {
		settingsMap["limit_allowed_http_method"] = nil
	}

	nextUpstreamList, ok := d.GetOk("next_upstream")
	if ok {
		nextUpstream := []string{}
		for _, upstream := range nextUpstreamList.([]interface{}) {
			nextUpstream = append(nextUpstream, upstream.(string))
		}
		settingsMap["next_upstream"] = nextUpstream
	} else {
		settingsMap["next_upstream"] = nil
	}

	limitTlsVersionList, ok := d.GetOk("limit_tls_version")
	if ok {
		limitTlsVersion := []string{}
		for _, version := range limitTlsVersionList.([]interface{}) {
			limitTlsVersion = append(limitTlsVersion, version.(string))
		}
		settingsMap["limit_tls_version"] = limitTlsVersion
	} else {
		settingsMap["limit_tls_version"] = nil
	}

	proxyCacheStaleList, ok := d.GetOk("proxy_cache_stale")
	if ok {
		proxyCacheStale := []string{}
		for _, stale := range proxyCacheStaleList.([]interface{}) {
			proxyCacheStale = append(proxyCacheStale, stale.(string))
		}
		settingsMap["proxy_cache_stale"] = proxyCacheStale
	} else {
		settingsMap["proxy_cache_stale"] = nil
	}

	wafLevelsEnableList, ok := d.GetOk("waf_levels_enable")
	if ok {
		wafLevelsEnable := []string{}
		for _, level := range wafLevelsEnableList.([]interface{}) {
			wafLevelsEnable = append(wafLevelsEnable, level.(string))
		}
		settingsMap["waf_levels_enable"] = wafLevelsEnable
	} else {
		settingsMap["waf_levels_enable"] = nil
	}

	return settingsMap, nil
}

func setSettingsDataByMap(d *schema.ResourceData, settings map[string]interface{}, subDomainName string, domainID int) {
	d.Set("subdomain_name", subDomainName)
	d.Set("domain_id", domainID)
	for k, v := range settings {
		d.Set(k, v)
	}
}

// setSettingsData ...
func setSettingsData(d *schema.ResourceData, settings *myrasec.Settings, subDomainName string, domainID int) {
	d.Set("subdomain_name", subDomainName)
	d.Set("domain_id", domainID)

	nextUpsteam, ok := d.GetOk("next_upstream")
	if ok {
		d.Set("next_upstream", nextUpsteam)
	}
	proxyConnectTimeout, ok := d.GetOk("proxy_connect_timeout")
	if ok {
		d.Set("proxy_connect_timeout", proxyConnectTimeout)
	}
	accessLog, ok := d.GetOk("access_log")
	if ok {
		d.Set("access_log", accessLog)
	}

	//d.Set("access_log", settings.AccessLog)
	//d.Set("antibot_post_flood", settings.AntibotPostFlood)
	//d.Set("antibot_post_flood_threshold", settings.AntibotPostFloodThreshold)
	//d.Set("antibot_proof_of_work", settings.AntibotProofOfWork)
	//d.Set("antibot_proof_of_work_threshold", settings.AntibotProofOfWorkThreshold)
	//d.Set("balancing_method", settings.BalancingMethod)
	//d.Set("block_not_whitelisted", settings.BlockNotWhitelisted)
	//d.Set("block_tor_network", settings.BlockTorNetwork)
	//d.Set("cache_enabled", settings.CacheEnabled)
	//d.Set("cache_revalidate", settings.CacheRevalidate)
	//d.Set("cdn", settings.CDN)
	//d.Set("client_max_body_size", settings.ClientMaxBodySize)
	//d.Set("diffie_hellman_exchange", settings.DiffieHellmanExchange)
	//d.Set("enable_origin_sni", settings.EnableOriginSNI)
	//d.Set("forwarded_for_replacement", settings.ForwardedForReplacement)
	//d.Set("hsts", settings.HSTS)
	//d.Set("hsts_include_subdomains", settings.HSTSIncludeSubdomains)
	//d.Set("hsts_max_age", settings.HSTSMaxAge)
	//d.Set("hsts_preload", settings.HSTSPreload)
	//d.Set("http_origin_port", settings.HTTPOriginPort)
	//d.Set("ignore_nocache", settings.IgnoreNoCache)
	//d.Set("image_optimization", settings.ImageOptimization)
	//d.Set("ipv6_active", settings.IPv6Active)
	//d.Set("limit_allowed_http_method", settings.LimitAllowedHTTPMethod)
	//d.Set("limit_tls_version", settings.LimitTLSVersion)
	//d.Set("log_format", settings.LogFormat)
	//d.Set("monitoring_alert_threshold", settings.MonitoringAlertThreshold)
	//d.Set("monitoring_contact_email", settings.MonitoringContactEMail)
	//d.Set("monitoring_send_alert", settings.MonitoringSendAlert)
	//d.Set("myra_ssl_header", settings.MyraSSLHeader)
	//d.Set("next_upstream", settings.NextUpstream)
	//d.Set("only_https", settings.OnlyHTTPS)
	//d.Set("origin_connection_header", settings.OriginConnectionHeader)
	//d.Set("proxy_cache_bypass", settings.ProxyCacheBypass)
	//d.Set("proxy_cache_stale", settings.ProxyCacheStale)
	//d.Set("proxy_connect_timeout", settings.ProxyConnectTimeout)
	//d.Set("proxy_read_timeout", settings.ProxyReadTimeout)
	//d.Set("request_limit_block", settings.RequestLimitBlock)
	//d.Set("request_limit_level", settings.RequestLimitLevel)
	//d.Set("request_limit_report", settings.RequestLimitReport)
	//d.Set("request_limit_report_email", settings.RequestLimitReportEMail)
	//d.Set("rewrite", settings.Rewrite)
	//d.Set("source_protocol", settings.SourceProtocol)
	//d.Set("spdy", settings.Spdy)
	//d.Set("ssl_origin_port", settings.SSLOriginPort)
	//d.Set("waf_enable", settings.WAFEnable)
	//d.Set("waf_levels_enable", settings.WAFLevelsEnable)
	//d.Set("waf_policy", settings.WAFPolicy)
	//d.Set("proxy_host_header", settings.ProxyHostHeader)
}
