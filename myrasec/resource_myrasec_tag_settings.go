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
				Required:    false,
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
			"waf_policy": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
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

	settings, err := buildTagSettings(d, false)
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

	_, err = client.UpdateTagSettingsPartial(settings, tag.ID)
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

	settings, err := buildTagSettings(d, false)
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

	_, err = client.UpdateTagSettingsPartial(settings, tag.ID)
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

	settings, err := buildTagSettings(d, true)
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

	_, err = client.UpdateTagSettingsPartial(settings, tag.ID)
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
func buildTagSettings(d *schema.ResourceData, clean bool) (map[string]interface{}, error) {
	tagSettingsMap := make(map[string]interface{})

	resource := resourceMyrasecTagSettings()
	for name, attr := range resource.Schema {
		if name == "tag_id" {
			continue
		}
		value, ok := d.GetOk(name)
		if ok && !clean {
			switch attr.Type {
			case schema.TypeBool:
				tagSettingsMap[name] = value.(bool)
			case schema.TypeInt:
				tagSettingsMap[name] = value.(int)
			case schema.TypeString:
				tagSettingsMap[name] = value.(string)
			case schema.TypeList:
				settingsList := []string{}
				for _, item := range value.([]interface{}) {
					settingsList = append(settingsList, item.(string))
				}
				tagSettingsMap[name] = settingsList
			}
		} else {
			tagSettingsMap[name] = nil
		}
	}

	return tagSettingsMap, nil
}

// setTagSettingsData ...
func setTagSettingsData(d *schema.ResourceData, settings *myrasec.Settings, tagId int) {
	d.Set("tag_id", tagId)

	_, ok := d.GetOk("access_log")
	if ok {
		d.Set("access_log", settings.AccessLog)
	}
	_, ok = d.GetOk("antibot_post_flood")
	if ok {
		d.Set("antibot_post_flood", settings.AntibotPostFlood)
	}
	_, ok = d.GetOk("antibot_post_flood_threshold")
	if ok {
		d.Set("antibot_post_flood_threshold", settings.AntibotPostFloodThreshold)
	}
	_, ok = d.GetOk("antibot_proof_of_work")
	if ok {
		d.Set("antibot_proof_of_work", settings.AntibotProofOfWork)
	}
	_, ok = d.GetOk("antibot_proof_of_work_threshold")
	if ok {
		d.Set("antibot_proof_of_work_threshold", settings.AntibotProofOfWorkThreshold)
	}
	_, ok = d.GetOk("balancing_method")
	if ok {
		d.Set("balancing_method", settings.BalancingMethod)
	}
	_, ok = d.GetOk("block_not_whitelisted")
	if ok {
		d.Set("block_not_whitelisted", settings.BlockNotWhitelisted)
	}
	_, ok = d.GetOk("block_tor_network")
	if ok {
		d.Set("block_tor_network", settings.BlockTorNetwork)
	}
	_, ok = d.GetOk("cache_enabled")
	if ok {
		d.Set("cache_enabled", settings.CacheEnabled)
	}
	_, ok = d.GetOk("cache_revalidate")
	if ok {
		d.Set("cache_revalidate", settings.CacheRevalidate)
	}
	_, ok = d.GetOk("cdn")
	if ok {
		d.Set("cdn", settings.CDN)
	}
	_, ok = d.GetOk("client_max_body_size")
	if ok {
		d.Set("client_max_body_size", settings.ClientMaxBodySize)
	}
	_, ok = d.GetOk("diffie_hellman_exchange")
	if ok {
		d.Set("diffie_hellman_exchange", settings.DiffieHellmanExchange)
	}
	_, ok = d.GetOk("enable_origin_sni")
	if ok {
		d.Set("enable_origin_sni", settings.EnableOriginSNI)
	}
	_, ok = d.GetOk("forwarded_for_replacement")
	if ok {
		d.Set("forwarded_for_replacement", settings.ForwardedForReplacement)
	}
	_, ok = d.GetOk("hsts")
	if ok {
		d.Set("hsts", settings.HSTS)
	}
	_, ok = d.GetOk("hsts_include_subdomains")
	if ok {
		d.Set("hsts_include_subdomains", settings.HSTSIncludeSubdomains)
	}
	_, ok = d.GetOk("hsts_max_age")
	if ok {
		d.Set("hsts_max_age", settings.HSTSMaxAge)
	}
	_, ok = d.GetOk("hsts_preload")
	if ok {
		d.Set("hsts_preload", settings.HSTSPreload)
	}
	_, ok = d.GetOk("http_origin_port")
	if ok {
		d.Set("http_origin_port", settings.HTTPOriginPort)
	}
	_, ok = d.GetOk("ignore_nocache")
	if ok {
		d.Set("ignore_nocache", settings.IgnoreNoCache)
	}
	_, ok = d.GetOk("image_optimization")
	if ok {
		d.Set("image_optimization", settings.ImageOptimization)
	}
	_, ok = d.GetOk("ipv6_active")
	if ok {
		d.Set("ipv6_active", settings.IPv6Active)
	}
	_, ok = d.GetOk("log_format")
	if ok {
		d.Set("log_format", settings.LogFormat)
	}
	_, ok = d.GetOk("monitoring_alert_threshold")
	if ok {
		d.Set("monitoring_alert_threshold", settings.MonitoringAlertThreshold)
	}
	_, ok = d.GetOk("monitoring_send_alert")
	if ok {
		d.Set("monitoring_send_alert", settings.MonitoringSendAlert)
	}
	_, ok = d.GetOk("myra_ssl_header")
	if ok {
		d.Set("myra_ssl_header", settings.MyraSSLHeader)
	}
	_, ok = d.GetOk("only_https")
	if ok {
		d.Set("only_https", settings.OnlyHTTPS)
	}
	_, ok = d.GetOk("origin_connection_header")
	if ok {
		d.Set("origin_connection_header", settings.OriginConnectionHeader)
	}
	_, ok = d.GetOk("proxy_connect_timeout")
	if ok {
		d.Set("proxy_connect_timeout", settings.ProxyConnectTimeout)
	}
	_, ok = d.GetOk("proxy_read_timeout")
	if ok {
		d.Set("proxy_read_timeout", settings.ProxyReadTimeout)
	}
	_, ok = d.GetOk("request_limit_block")
	if ok {
		d.Set("request_limit_block", settings.RequestLimitBlock)
	}
	_, ok = d.GetOk("request_limit_level")
	if ok {
		d.Set("request_limit_level", settings.RequestLimitLevel)
	}
	_, ok = d.GetOk("request_limit_report")
	if ok {
		d.Set("request_limit_report", settings.RequestLimitReport)
	}
	_, ok = d.GetOk("rewrite")
	if ok {
		d.Set("rewrite", settings.Rewrite)
	}
	_, ok = d.GetOk("source_protocol")
	if ok {
		d.Set("source_protocol", settings.SourceProtocol)
	}
	_, ok = d.GetOk("spdy")
	if ok {
		d.Set("spdy", settings.Spdy)
	}
	_, ok = d.GetOk("ssl_origin_port")
	if ok {
		d.Set("ssl_origin_port", settings.SSLOriginPort)
	}
	_, ok = d.GetOk("waf_enable")
	if ok {
		d.Set("waf_enable", settings.WAFEnable)
	}
	_, ok = d.GetOk("waf_policy")
	if ok {
		d.Set("waf_policy", settings.WAFPolicy)
	}
}
