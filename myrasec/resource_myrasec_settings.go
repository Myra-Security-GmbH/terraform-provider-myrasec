package myrasec

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go"
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

//
// resourceMyrasecSettings ...
//
func resourceMyrasecSettings() *schema.Resource {
	return &schema.Resource{
		Create: resourceMyrasecSettingsCreate,
		Read:   resourceMyrasecSettingsRead,
		Delete: resourceMyrasecSettingsDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the Settings.",
			},
			"access_log": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAccessLog,
				ForceNew:    true,
				Description: "Activate separated access log",
			},
			"antibot_post_flood": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotPostFlood,
				ForceNew:    true,
				Description: "Detection of POST floods by using a JavaScript based puzzle.",
			},
			"antibot_post_flood_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotPostFloodThreshold,
				ForceNew:    true,
				Description: "This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved.",
			},
			"antibot_proof_of_work": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotProofOfWork,
				ForceNew:    true,
				Description: "Detection of valid clients by using a JavaScript based puzzle.",
			},
			"antibot_proof_of_work_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotProofOfWorkThreshold,
				ForceNew:    true,
				Description: "This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved.",
			},
			"balancing_method": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueBalancingMethod,
				ValidateFunc: validation.StringInSlice([]string{"round_robin", "ip_hash", "least_conn"}, false),
				ForceNew:     true,
				Description:  "Specifies with which method requests are balanced between upstream servers.",
			},
			"block_not_whitelisted": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueBlockNotWhitelisted,
				ForceNew:    true,
				Description: "Block all IPs, which are not whitelisted.",
			},
			"block_tor_network": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueBlockTorNetwork,
				ForceNew:    true,
				Description: "Block traffic from the TOR network.",
			},
			"cache_enabled": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueCacheEnabled,
				ForceNew:    true,
				Description: "Turn caching on or off.",
			},
			"cache_revalidate": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueCacheRevalidate,
				ForceNew:    true,
				Description: "Enable stale cache item revalidation.",
			},
			"cdn": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueCDN,
				ForceNew:    true,
				Description: "Use subdomain as Content Delivery Node (CDN).",
			},
			"client_max_body_size": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueClientMaxBodySize,
				ForceNew:    true,
				Description: "Sets the maximum allowed size of the client request body, specified in the “Content-Length” request header field. Maximum 100MB.",
			},
			"diffie_hellman_exchange": {
				Type:         schema.TypeInt,
				Required:     false,
				Optional:     true,
				Default:      defaultValueDiffieHellmanExchange,
				ValidateFunc: validation.IntInSlice([]int{1024, 2048}),
				ForceNew:     true,
				Description:  "The Diffie-Hellman key exchange parameter length.",
			},
			"enable_origin_sni": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueEnableOriginSNI,
				ForceNew:    true,
				Description: "Enable or disable origin SNI.",
			},
			"forwarded_for_replacement": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Default:     defaultValueForwardedForReplacement,
				ForceNew:    true,
				Description: "Set your own X-Forwarded-For header.",
			},
			"hsts": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTS,
				ForceNew:    true,
				Description: "HSTS Strict Transport Security (HSTS).",
			},
			"hsts_include_subdomains": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTSIncludeSubdomains,
				ForceNew:    true,
				Description: "HSTS includeSubDomains directive.",
			},
			"hsts_max_age": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTSMaxAge,
				ForceNew:    true,
				Description: "HSTS max-age.",
			},
			"hsts_preload": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTSPreload,
				ForceNew:    true,
				Description: "HSTS preload directive.",
			},
			"http_origin_port": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHTTPOriginPort,
				ForceNew:    true,
				Description: "Allows to set a port for communication with origin via HTTP.",
			},
			"ignore_nocache": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueIgnoreNoCache,
				ForceNew:    true,
				Description: "If activated, no-cache headers (Cache-Control: [private|no-store|no-cache]) will be ignored.",
			},
			"image_optimization": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueImageOptimization,
				ForceNew:    true,
				Description: "Optimization of images.",
			},
			"ipv6_active": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueIPv6Active,
				ForceNew:    true,
				Description: "Allow connections via IPv6 to your systems.",
			},
			"limit_allowed_http_method": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew:    true,
				Description: "Not selected HTTP methods will be blocked.",
			},
			"limit_tls_version": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew:    true,
				Description: "Only selected TLS versions will be used.",
			},
			"log_format": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Default:     defaultValueLogFormat,
				ForceNew:    true,
				Description: "Use a different log format.",
			},
			"monitoring_alert_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueMonitoringAlertThreshold,
				ForceNew:    true,
				Description: "Errors per minute that must occur until a report is sent.",
			},
			"monitoring_contact_email": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Default:     defaultValueMonitoringContactEMail,
				ForceNew:    true,
				Description: "Email addresses, to which monitoring emails should be send. Multiple addresses are separated with a space.",
			},
			"monitoring_send_alert": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueMonitoringSendAlert,
				ForceNew:    true,
				Description: "Enables / disables the upstream error reporting.",
			},
			"myra_ssl_header": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueMyraSSLHeader,
				ForceNew:    true,
				Description: "Activates the X-Myra-SSL Header.",
			},
			"next_upstream": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew:    true,
				Description: "Specifies the error that mark the current upstream as \"down\".",
			},
			"only_https": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueOnlyHTTPS,
				ForceNew:    true,
				Description: "Shall the origin server always be requested via HTTPS?",
			},
			"origin_connection_header": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueOriginConnectionHeader,
				ValidateFunc: validation.StringInSlice([]string{"none", "close", "upgrade"}, false),
				ForceNew:     true,
				Description:  "Connection header.",
			},
			"proxy_cache_bypass": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Default:     defaultValueProxyCacheBypass,
				ForceNew:    true,
				Description: "Name of the cookie which forces Myra to deliver the response not from cache.",
			},
			"proxy_cache_stale": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew:    true,
				Description: "Determines in which cases a stale cached response can be used when an error occurs.",
			},
			"proxy_connect_timeout": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueProxyConnectTimeout,
				ForceNew:    true,
				Description: "Timeout for establishing a connection to the upstream server.",
			},
			"proxy_read_timeout": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueProxyReadTimeout,
				ForceNew:    true,
				Description: "Timeout for reading the upstream response.",
			},
			"request_limit_block": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueRequestLimitBlock,
				ValidateFunc: validation.StringInSlice([]string{"CAPTCHA", "HTTP429", "no"}, false),
				ForceNew:     true,
				Description:  "Show CAPTCHA after exceeding the configured request limit.",
			},
			"request_limit_level": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueRequestLimitLevel,
				ForceNew:    true,
				Description: "Sets how many requests are allowed from an IP per minute.",
			},
			"request_limit_report": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueRequestLimitReport,
				ForceNew:    true,
				Description: "If activated, an email will be send containing blocked ip addresses that exceeded the configured request limit.",
			},
			"request_limit_report_email": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Default:     defaultValueRequestLimitReportEMail,
				ForceNew:    true,
				Description: "Email addresses, to which request limit emails should be send. Multiple addresses are separated with a space.",
			},
			"rewrite": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueRewrite,
				ForceNew:    true,
				Description: "Enable the JavaScript optimization.",
			},
			"source_protocol": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueSourceProtocol,
				ValidateFunc: validation.StringInSlice([]string{"same", "http", "https"}, false),
				ForceNew:     true,
				Description:  "Protocol to query the origin server.",
			},
			"spdy": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueSpdy,
				ForceNew:    true,
				Description: "Activates the SPDY protocol.",
			},
			"ssl_origin_port": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueSSLOriginPort,
				ForceNew:    true,
				Description: "Allows to set a port for communication with origin via SSL.",
			},
			"waf_enable": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueWAFEnable,
				ForceNew:    true,
				Description: "Enables / disables the Web Application Firewall.",
			},
			"waf_levels_enable": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew:    true,
				Description: "Level of applied WAF rules.",
			},
			"waf_policy": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueWAFPolicy,
				ValidateFunc: validation.StringInSlice([]string{"allow", "block"}, false),
				ForceNew:     true,
				Description:  "Default policy for the Web Application Firewall in case of rule error.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecSettingsCreate ...
//
func resourceMyrasecSettingsCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	settings, err := buildSettings(d, meta)
	if err != nil {
		return fmt.Errorf("Error building settings: %s", err)
	}

	_, err = client.UpdateSettings(settings, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error creating cache setting: %s", err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return resourceMyrasecSettingsRead(d, meta)
}

//
// resourceMyrasecSettingsRead ...
//
func resourceMyrasecSettingsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	settings, err := client.ListSettings(d.Get("subdomain_name").(string), nil)
	if err != nil {
		return fmt.Errorf("Error fetching settings: %s", err)
	}

	d.Set("access_log", settings.AccessLog)
	d.Set("antibot_post_flood", settings.AntibotPostFlood)
	d.Set("antibot_post_flood_threshold", settings.AntibotPostFloodThreshold)
	d.Set("antibot_proof_of_work", settings.AntibotProofOfWork)
	d.Set("antibot_proof_of_work_threshold", settings.AntibotProofOfWorkThreshold)
	d.Set("balancing_method", settings.BalancingMethod)
	d.Set("block_not_whitelisted", settings.BlockNotWhitelisted)
	d.Set("block_tor_network", settings.BlockTorNetwork)
	d.Set("cache_enabled", settings.CacheEnabled)
	d.Set("cache_revalidate", settings.CacheRevalidate)
	d.Set("cdn", settings.CDN)
	d.Set("client_max_body_size", settings.ClientMaxBodySize)
	d.Set("diffie_hellman_exchange", settings.DiffieHellmanExchange)
	d.Set("enable_origin_sni", settings.EnableOriginSNI)
	d.Set("forwarded_for_replacement", settings.ForwardedForReplacement)
	d.Set("hsts", settings.HSTS)
	d.Set("hsts_include_subdomains", settings.HSTSIncludeSubdomains)
	d.Set("hsts_max_age", settings.HSTSMaxAge)
	d.Set("hsts_preload", settings.HSTSPreload)
	d.Set("http_origin_port", settings.HTTPOriginPort)
	d.Set("ignore_nocache", settings.IgnoreNoCache)
	d.Set("image_optimization", settings.ImageOptimization)
	d.Set("ipv6_active", settings.IPv6Active)
	d.Set("limit_allowed_http_method", settings.LimitAllowedHTTPMethod)
	d.Set("limit_tls_version", settings.LimitTLSVersion)
	d.Set("log_format", settings.LogFormat)
	d.Set("monitoring_alert_threshold", settings.MonitoringAlertThreshold)
	d.Set("monitoring_contact_email", settings.MonitoringContactEMail)
	d.Set("monitoring_send_alert", settings.MonitoringSendAlert)
	d.Set("myra_ssl_header", settings.MyraSSLHeader)
	d.Set("next_upstream", settings.NextUpstream)
	d.Set("only_https", settings.OnlyHTTPS)
	d.Set("origin_connection_header", settings.OriginConnectionHeader)
	d.Set("proxy_cache_bypass", settings.ProxyCacheBypass)
	d.Set("proxy_cache_stale", settings.ProxyCacheStale)
	d.Set("proxy_connect_timeout", settings.ProxyConnectTimeout)
	d.Set("proxy_read_timeout", settings.ProxyReadTimeout)
	d.Set("request_limit_block", settings.RequestLimitBlock)
	d.Set("request_limit_level", settings.RequestLimitLevel)
	d.Set("request_limit_report", settings.RequestLimitReport)
	d.Set("request_limit_report_email", settings.RequestLimitReportEMail)
	d.Set("rewrite", settings.Rewrite)
	d.Set("source_protocol", settings.SourceProtocol)
	d.Set("spdy", settings.Spdy)
	d.Set("ssl_origin_port", settings.SSLOriginPort)
	d.Set("waf_enable", settings.WAFEnable)
	d.Set("waf_levels_enable", settings.WAFLevelsEnable)
	d.Set("waf_policy", settings.WAFPolicy)

	return nil
}

//
// resourceMyrasecSettingsDelete restores the default setting values
//
func resourceMyrasecSettingsDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing setting id: %s", err)
	}

	log.Printf("[INFO] Deleting settings: %v", settingID)

	settings, err := buildDefaultSettings(d, meta)
	if err != nil {
		return fmt.Errorf("Error building settings: %s", err)
	}

	_, err = client.UpdateSettings(settings, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error deleting settings: %s", err)
	}
	return err
}

//
// buildSettings ...
//
func buildSettings(d *schema.ResourceData, meta interface{}) (*myrasec.Settings, error) {
	settings := &myrasec.Settings{
		AccessLog:                   d.Get("access_log").(bool),
		AntibotPostFlood:            d.Get("antibot_post_flood").(bool),
		AntibotPostFloodThreshold:   d.Get("antibot_post_flood_threshold").(int),
		AntibotProofOfWork:          d.Get("antibot_proof_of_work").(bool),
		AntibotProofOfWorkThreshold: d.Get("antibot_proof_of_work_threshold").(int),
		BalancingMethod:             d.Get("balancing_method").(string),
		BlockNotWhitelisted:         d.Get("block_not_whitelisted").(bool),
		BlockTorNetwork:             d.Get("block_tor_network").(bool),
		CacheEnabled:                d.Get("cache_enabled").(bool),
		CacheRevalidate:             d.Get("cache_revalidate").(bool),
		CDN:                         d.Get("cdn").(bool),
		ClientMaxBodySize:           d.Get("client_max_body_size").(int),
		DiffieHellmanExchange:       d.Get("diffie_hellman_exchange").(int),
		EnableOriginSNI:             d.Get("enable_origin_sni").(bool),
		ForwardedForReplacement:     d.Get("forwarded_for_replacement").(string),
		HSTS:                        d.Get("hsts").(bool),
		HSTSIncludeSubdomains:       d.Get("hsts_include_subdomains").(bool),
		HSTSMaxAge:                  d.Get("hsts_max_age").(int),
		HSTSPreload:                 d.Get("hsts_preload").(bool),
		HTTPOriginPort:              d.Get("http_origin_port").(int),
		IgnoreNoCache:               d.Get("ignore_nocache").(bool),
		ImageOptimization:           d.Get("image_optimization").(bool),
		IPv6Active:                  d.Get("ipv6_active").(bool),
		LogFormat:                   d.Get("log_format").(string),
		MonitoringAlertThreshold:    d.Get("monitoring_alert_threshold").(int),
		MonitoringContactEMail:      d.Get("monitoring_contact_email").(string),
		MonitoringSendAlert:         d.Get("monitoring_send_alert").(bool),
		MyraSSLHeader:               d.Get("myra_ssl_header").(bool),
		OnlyHTTPS:                   d.Get("only_https").(bool),
		OriginConnectionHeader:      d.Get("origin_connection_header").(string),
		ProxyCacheBypass:            d.Get("proxy_cache_bypass").(string),
		ProxyConnectTimeout:         d.Get("proxy_connect_timeout").(int),
		ProxyReadTimeout:            d.Get("proxy_read_timeout").(int),
		RequestLimitBlock:           d.Get("request_limit_block").(string),
		RequestLimitLevel:           d.Get("request_limit_level").(int),
		RequestLimitReport:          d.Get("request_limit_report").(bool),
		RequestLimitReportEMail:     d.Get("request_limit_report_email").(string),
		Rewrite:                     d.Get("rewrite").(bool),
		SourceProtocol:              d.Get("source_protocol").(string),
		Spdy:                        d.Get("spdy").(bool),
		SSLOriginPort:               d.Get("ssl_origin_port").(int),
		WAFEnable:                   d.Get("waf_enable").(bool),
		WAFPolicy:                   d.Get("waf_policy").(string),
	}

	for _, method := range d.Get("limit_allowed_http_method").([]interface{}) {
		settings.LimitAllowedHTTPMethod = append(settings.LimitAllowedHTTPMethod, method.(string))
	}

	for _, upstream := range d.Get("next_upstream").([]interface{}) {
		settings.NextUpstream = append(settings.NextUpstream, upstream.(string))
	}

	for _, version := range d.Get("limit_tls_version").([]interface{}) {
		settings.LimitTLSVersion = append(settings.LimitTLSVersion, version.(string))
	}

	for _, stale := range d.Get("proxy_cache_stale").([]interface{}) {
		settings.ProxyCacheStale = append(settings.ProxyCacheStale, stale.(string))
	}

	for _, level := range d.Get("waf_levels_enable").([]interface{}) {
		settings.WAFLevelsEnable = append(settings.WAFLevelsEnable, level.(string))
	}

	return settings, nil
}

//
// buildDefaultSettings ...
//
func buildDefaultSettings(d *schema.ResourceData, meta interface{}) (*myrasec.Settings, error) {
	settings := &myrasec.Settings{
		AccessLog:                   defaultValueAccessLog,
		AntibotPostFlood:            defaultValueAntibotPostFlood,
		AntibotPostFloodThreshold:   defaultValueAntibotPostFloodThreshold,
		AntibotProofOfWork:          defaultValueAntibotProofOfWork,
		AntibotProofOfWorkThreshold: defaultValueAntibotProofOfWorkThreshold,
		BalancingMethod:             defaultValueBalancingMethod,
		BlockNotWhitelisted:         defaultValueBlockNotWhitelisted,
		BlockTorNetwork:             defaultValueBlockTorNetwork,
		CacheEnabled:                defaultValueCacheEnabled,
		CacheRevalidate:             defaultValueCacheRevalidate,
		CDN:                         defaultValueCDN,
		ClientMaxBodySize:           defaultValueClientMaxBodySize,
		DiffieHellmanExchange:       defaultValueDiffieHellmanExchange,
		EnableOriginSNI:             defaultValueEnableOriginSNI,
		ForwardedForReplacement:     defaultValueForwardedForReplacement,
		HSTS:                        defaultValueHSTS,
		HSTSIncludeSubdomains:       defaultValueHSTSIncludeSubdomains,
		HSTSMaxAge:                  defaultValueHSTSMaxAge,
		HSTSPreload:                 defaultValueHSTSPreload,
		HTTPOriginPort:              defaultValueHTTPOriginPort,
		IgnoreNoCache:               defaultValueIgnoreNoCache,
		ImageOptimization:           defaultValueImageOptimization,
		IPv6Active:                  defaultValueIPv6Active,
		LogFormat:                   defaultValueLogFormat,
		MonitoringAlertThreshold:    defaultValueMonitoringAlertThreshold,
		MonitoringContactEMail:      defaultValueMonitoringContactEMail,
		MonitoringSendAlert:         defaultValueMonitoringSendAlert,
		MyraSSLHeader:               defaultValueMyraSSLHeader,
		OnlyHTTPS:                   defaultValueOnlyHTTPS,
		OriginConnectionHeader:      defaultValueOriginConnectionHeader,
		ProxyCacheBypass:            defaultValueProxyCacheBypass,
		ProxyConnectTimeout:         defaultValueProxyConnectTimeout,
		ProxyReadTimeout:            defaultValueProxyReadTimeout,
		RequestLimitBlock:           defaultValueRequestLimitBlock,
		RequestLimitLevel:           defaultValueRequestLimitLevel,
		RequestLimitReport:          defaultValueRequestLimitReport,
		RequestLimitReportEMail:     defaultValueRequestLimitReportEMail,
		Rewrite:                     defaultValueRewrite,
		SourceProtocol:              defaultValueSourceProtocol,
		Spdy:                        defaultValueSpdy,
		SSLOriginPort:               defaultValueSSLOriginPort,
		WAFEnable:                   defaultValueWAFEnable,
		WAFPolicy:                   defaultValueWAFPolicy,
		LimitAllowedHTTPMethod:      nil,
		NextUpstream:                []string{"error", "timeout", "invalid_header"},
		LimitTLSVersion:             []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
		ProxyCacheStale:             []string{"updating"},
		WAFLevelsEnable:             []string{"waf_tag", "waf_domain", "waf_subdomain"},
	}

	return settings, nil
}
