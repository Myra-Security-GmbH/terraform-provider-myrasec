package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// resourceMyrasecTagSettings
func resourceMyrasecTagSettings() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecTagSettingsCreate,
		ReadContext:   resourceMyrasecTagSettingsRead,
		UpdateContext: resourceMyrasecTagSettingsUpdate,
		DeleteContext: resourceMyrasecTagSettingsDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"tag_id": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "The tagID for the settings",
			},
			"access_log": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAccessLog,
				Description: "Activate separated access log",
			},
			"antibot_post_flood": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotPostFlood,
				Description: "Detection of POST floods by using a JavaScript based puzzle.",
			},
			"antibot_post_flood_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotPostFloodThreshold,
				Description: "This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved.",
			},
			"antibot_proof_of_work": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotProofOfWork,
				Description: "Detection of valid clients by using a JavaScript based puzzle.",
			},
			"antibot_proof_of_work_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueAntibotProofOfWorkThreshold,
				Description: "This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved.",
			},
			"balancing_method": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueBalancingMethod,
				ValidateFunc: validation.StringInSlice([]string{"round_robin", "ip_hash", "least_conn"}, false),
				Description:  "Specifies with which method requests are balanced between upstream servers.",
			},
			"block_not_whitelisted": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueBlockNotWhitelisted,
				Description: "Block all IPs, which are not whitelisted.",
			},
			"block_tor_network": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueBlockTorNetwork,
				Description: "Block traffic from the TOR network.",
			},
			"cache_enabled": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueCacheEnabled,
				Description: "Turn caching on or off.",
			},
			"cache_revalidate": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueCacheRevalidate,
				Description: "Enable stale cache item revalidation.",
			},
			"cdn": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueCDN,
				Description: "Use subdomain as Content Delivery Node (CDN).",
			},
			"client_max_body_size": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueClientMaxBodySize,
				Description: "Sets the maximum allowed size of the client request body, specified in the “Content-Length” request header field. Maximum 100MB.",
			},
			"diffie_hellman_exchange": {
				Type:         schema.TypeInt,
				Required:     false,
				Optional:     true,
				Default:      defaultValueDiffieHellmanExchange,
				ValidateFunc: validation.IntInSlice([]int{1024, 2048}),
				Description:  "The Diffie-Hellman key exchange parameter length.",
			},
			"enable_origin_sni": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueEnableOriginSNI,
				Description: "Enable or disable origin SNI.",
			},
			"forwarded_for_replacement": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Default:     defaultValueForwardedForReplacement,
				Description: "Set your own X-Forwarded-For header.",
			},
			"hsts": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTS,
				Description: "HSTS Strict Transport Security (HSTS).",
			},
			"hsts_include_subdomains": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTSIncludeSubdomains,
				Description: "HSTS includeSubDomains directive.",
			},
			"hsts_max_age": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTSMaxAge,
				Description: "HSTS max-age.",
			},
			"hsts_preload": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHSTSPreload,
				Description: "HSTS preload directive.",
			},
			"http_origin_port": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueHTTPOriginPort,
				Description: "Allows to set a port for communication with origin via HTTP.",
			},
			"ignore_nocache": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueIgnoreNoCache,
				Description: "If activated, no-cache headers (Cache-Control: [private|no-store|no-cache]) will be ignored.",
			},
			"image_optimization": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueImageOptimization,
				Description: "Optimization of images.",
			},
			"ipv6_active": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueIPv6Active,
				Description: "Allow connections via IPv6 to your systems.",
			},
			"log_format": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Default:     defaultValueLogFormat,
				Description: "Use a different log format.",
			},
			"monitoring_alert_threshold": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueMonitoringAlertThreshold,
				Description: "Errors per minute that must occur until a report is sent.",
			},
			"monitoring_send_alert": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueMonitoringSendAlert,
				Description: "Enables / disables the upstream error reporting.",
			},
			"myra_ssl_header": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueMyraSSLHeader,
				Description: "Activates the X-Myra-SSL Header.",
			},
			"only_https": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueOnlyHTTPS,
				Description: "Shall the origin server always be requested via HTTPS?",
			},
			"origin_connection_header": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueOriginConnectionHeader,
				ValidateFunc: validation.StringInSlice([]string{"none", "close", "upgrade"}, false),
				Description:  "Connection header.",
			},
			"proxy_connect_timeout": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueProxyConnectTimeout,
				Description: "Timeout for establishing a connection to the upstream server.",
			},
			"proxy_read_timeout": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueProxyReadTimeout,
				Description: "Timeout for reading the upstream response.",
			},
			"request_limit_block": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueRequestLimitBlock,
				ValidateFunc: validation.StringInSlice([]string{"CAPTCHA", "HTTP429", "no"}, false),
				Description:  "Show CAPTCHA after exceeding the configured request limit.",
			},
			"request_limit_level": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueRequestLimitLevel,
				Description: "Sets how many requests are allowed from an IP per minute.",
			},
			"request_limit_report": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueRequestLimitReport,
				Description: "If activated, an email will be send containing blocked ip addresses that exceeded the configured request limit.",
			},
			"rewrite": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueRewrite,
				Description: "Enable the JavaScript optimization.",
			},
			"source_protocol": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueSourceProtocol,
				ValidateFunc: validation.StringInSlice([]string{"same", "http", "https"}, false),
				Description:  "Protocol to query the origin server.",
			},
			"spdy": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueSpdy,
				Description: "Activates the SPDY protocol.",
			},
			"ssl_origin_port": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Default:     defaultValueSSLOriginPort,
				Description: "Allows to set a port for communication with origin via SSL.",
			},
			"waf_enable": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Default:     defaultValueWAFEnable,
				Description: "Enables / disables the Web Application Firewall.",
			},
			"waf_policy": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Default:      defaultValueWAFPolicy,
				ValidateFunc: validation.StringInSlice([]string{"allow", "block"}, false),
				Description:  "Default policy for the Web Application Firewall in case of rule error.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecTagSettingsCreate
func resourceMyrasecTagSettingsCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settings, err := buildTagSettings(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building tag settings",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID := d.Get("tag_id").(int)
	tag, err := client.GetTag(tagID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching tag",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.UpdateTagSettings(settings, tag.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating tag settings",
		})
		return diags
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return resourceMyrasecTagSettingsRead(ctx, d, meta)
}

// resourceMyrasecTagSettingsRead ...
func resourceMyrasecTagSettingsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	tagId := d.Get("tag_id")
	settings, err := client.ListTagSettings(tagId.(int))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching tag settings",
			Detail:   formatError(err),
		})
		return diags
	}

	setTagSettingsData(d, settings, tagId.(int))

	return diags
}

// resourceMyrasecTagSettingsUpdate
func resourceMyrasecTagSettingsUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settings, err := buildTagSettings(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building tag settings",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID := d.Get("tag_id").(int)
	tag, err := client.GetTag(tagID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching tag",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.UpdateTagSettings(settings, tag.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating tag settings",
		})
		return diags
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return resourceMyrasecTagSettingsRead(ctx, d, meta)
}

// resourceMyrasecTagSettingsDelete
func resourceMyrasecTagSettingsDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing tag setting ID",
			Detail:   formatError(err),
		})
		return diags
	}
	log.Printf("[INFO] Deleting settings: %v", settingID)

	settings, err := buildDefaultTagSettings(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building tag settings",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID := d.Get("tag_id").(int)
	tag, err := client.GetTag(tagID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching tag for given ID",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.UpdateTagSettings(settings, tag.ID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting tag settings",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// buildTagSettings ...
func buildTagSettings(d *schema.ResourceData, meta interface{}) (*myrasec.Settings, error) {
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
		MonitoringSendAlert:         d.Get("monitoring_send_alert").(bool),
		MyraSSLHeader:               d.Get("myra_ssl_header").(bool),
		OnlyHTTPS:                   d.Get("only_https").(bool),
		OriginConnectionHeader:      d.Get("origin_connection_header").(string),
		ProxyConnectTimeout:         d.Get("proxy_connect_timeout").(int),
		ProxyReadTimeout:            d.Get("proxy_read_timeout").(int),
		RequestLimitBlock:           d.Get("request_limit_block").(string),
		RequestLimitLevel:           d.Get("request_limit_level").(int),
		RequestLimitReport:          d.Get("request_limit_report").(bool),
		Rewrite:                     d.Get("rewrite").(bool),
		SourceProtocol:              d.Get("source_protocol").(string),
		Spdy:                        d.Get("spdy").(bool),
		SSLOriginPort:               d.Get("ssl_origin_port").(int),
		WAFEnable:                   d.Get("waf_enable").(bool),
		WAFPolicy:                   d.Get("waf_policy").(string),
	}

	return settings, nil
}

// buildDefaultTagSettings ...
func buildDefaultTagSettings(d *schema.ResourceData, meta interface{}) (*myrasec.Settings, error) {
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
		MonitoringSendAlert:         defaultValueMonitoringSendAlert,
		MyraSSLHeader:               defaultValueMyraSSLHeader,
		OnlyHTTPS:                   defaultValueOnlyHTTPS,
		OriginConnectionHeader:      defaultValueOriginConnectionHeader,
		ProxyConnectTimeout:         defaultValueProxyConnectTimeout,
		ProxyReadTimeout:            defaultValueProxyReadTimeout,
		RequestLimitBlock:           defaultValueRequestLimitBlock,
		RequestLimitLevel:           defaultValueRequestLimitLevel,
		RequestLimitReport:          defaultValueRequestLimitReport,
		Rewrite:                     defaultValueRewrite,
		SourceProtocol:              defaultValueSourceProtocol,
		Spdy:                        defaultValueSpdy,
		SSLOriginPort:               defaultValueSSLOriginPort,
		WAFEnable:                   defaultValueWAFEnable,
		WAFPolicy:                   defaultValueWAFPolicy,
	}

	return settings, nil
}

// setTagSettingsData ...
func setTagSettingsData(d *schema.ResourceData, settings *myrasec.Settings, tagId int) {
	d.Set("tag_id", tagId)
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
	d.Set("log_format", settings.LogFormat)
	d.Set("monitoring_alert_threshold", settings.MonitoringAlertThreshold)
	d.Set("monitoring_send_alert", settings.MonitoringSendAlert)
	d.Set("myra_ssl_header", settings.MyraSSLHeader)
	d.Set("only_https", settings.OnlyHTTPS)
	d.Set("origin_connection_header", settings.OriginConnectionHeader)
	d.Set("proxy_connect_timeout", settings.ProxyConnectTimeout)
	d.Set("proxy_read_timeout", settings.ProxyReadTimeout)
	d.Set("request_limit_block", settings.RequestLimitBlock)
	d.Set("request_limit_level", settings.RequestLimitLevel)
	d.Set("request_limit_report", settings.RequestLimitReport)
	d.Set("rewrite", settings.Rewrite)
	d.Set("source_protocol", settings.SourceProtocol)
	d.Set("spdy", settings.Spdy)
	d.Set("ssl_origin_port", settings.SSLOriginPort)
	d.Set("waf_enable", settings.WAFEnable)
	d.Set("waf_policy", settings.WAFPolicy)
}
