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

func dataSourceMyrasecTagSettings() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecTagSettingsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tag_id": {
							Type:     schema.TypeInt,
							Required: true,
						},
					},
				},
			},
			"settings": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tag_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"access_log": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"antibot_post_flood": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"antibot_post_flood_threshold": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"antibot_proof_of_work": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"antibot_proof_of_work_threshold": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"balancing_method": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"block_not_whitelisted": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"block_tor_network": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"cache_enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"cache_revalidate": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"cdn": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"client_max_body_size": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"cookie_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"diffie_hellman_exchange": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"disable_forwarded_for": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"enable_origin_sni": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"enforce_cache_ttl": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"forwarded_for_replacement": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"hsts": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"hsts_include_subdomains": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"hsts_max_age": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"hsts_preload": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"http_origin_port": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"ignore_nocache": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"image_optimization": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"ip_lock": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"ipv6_active": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"limit_allowed_http_method": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"limit_tls_version": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"log_format": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"monitoring_alert_threshold": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"monitoring_contact_email": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"monitoring_send_alert": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"myra_ssl_certificate": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"myra_ssl_certificate_key": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"myra_ssl_header": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"next_upstream": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"only_https": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"origin_connection_header": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"proxy_cache_bypass": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"proxy_cache_stale": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"proxy_connect_timeout": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"proxy_read_timeout": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"request_limit_block": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"request_limit_level": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"request_limit_report": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"request_limit_report_email": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"rewrite": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"source_protocol": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"spdy": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"ssl_client_verify": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ssl_client_certificate": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ssl_client_header_verification": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ssl_client_header_fingerprint": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ssl_origin_port": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"waf_enable": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"waf_levels_enable": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"waf_policy": {
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

func dataSourceMyrasecTagSettingsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareTagSettingsFilter(d.Get("filter"))
	if f == nil {
		f = &tagSettingsFilter{}
	}

	settings, diags := listTagSettings(meta, f.tagID)
	if diags.HasError() {
		return diags
	}

	settingData := make([]interface{}, 0)
	settingData = append(settingData, map[string]interface{}{
		"tag_id":                          f.tagID,
		"access_log":                      settings.AccessLog,
		"antibot_post_flood":              settings.AntibotPostFlood,
		"antibot_post_flood_threshold":    settings.AntibotPostFloodThreshold,
		"antibot_proof_of_work":           settings.AntibotProofOfWork,
		"antibot_proof_of_work_threshold": settings.AntibotProofOfWorkThreshold,
		"balancing_method":                settings.BalancingMethod,
		"block_not_whitelisted":           settings.BlockNotWhitelisted,
		"block_tor_network":               settings.BlockTorNetwork,
		"cache_enabled":                   settings.CacheEnabled,
		"cache_revalidate":                settings.CacheRevalidate,
		"cdn":                             settings.CDN,
		"client_max_body_size":            settings.ClientMaxBodySize,
		"cookie_name":                     settings.CookieName,
		"diffie_hellman_exchange":         settings.DiffieHellmanExchange,
		"disable_forwarded_for":           settings.DisableForwardFor,
		"enable_origin_sni":               settings.EnableOriginSNI,
		"enforce_cache_ttl":               settings.EnforceCacheTTL,
		"forwarded_for_replacement":       settings.ForwardedForReplacement,
		"hsts":                            settings.HSTS,
		"hsts_include_subdomains":         settings.HSTSIncludeSubdomains,
		"hsts_max_age":                    settings.HSTSMaxAge,
		"hsts_preload":                    settings.HSTSPreload,
		"http_origin_port":                settings.HTTPOriginPort,
		"ignore_nocache":                  settings.IgnoreNoCache,
		"image_optimization":              settings.ImageOptimization,
		"ip_lock":                         settings.IPLock,
		"ipv6_active":                     settings.IPv6Active,
		"limit_allowed_http_method":       settings.LimitAllowedHTTPMethod,
		"limit_tls_version":               settings.LimitTLSVersion,
		"log_format":                      settings.LogFormat,
		"monitoring_alert_threshold":      settings.MonitoringAlertThreshold,
		"monitoring_contact_email":        settings.MonitoringContactEMail,
		"monitoring_send_alert":           settings.MonitoringSendAlert,
		"myra_ssl_header":                 settings.MyraSSLHeader,
		"myra_ssl_certificate":            settings.MyraSSLCertificate,
		"myra_ssl_certificate_key":        settings.MyraSSLCertificateKey,
		"next_upstream":                   settings.NextUpstream,
		"only_https":                      settings.OnlyHTTPS,
		"origin_connection_header":        settings.OriginConnectionHeader,
		"proxy_cache_bypass":              settings.ProxyCacheBypass,
		"proxy_cache_stale":               settings.ProxyCacheStale,
		"proxy_connect_timeout":           settings.ProxyConnectTimeout,
		"proxy_read_timeout":              settings.ProxyReadTimeout,
		"request_limit_block":             settings.RequestLimitBlock,
		"request_limit_level":             settings.RequestLimitLevel,
		"request_limit_report":            settings.RequestLimitReport,
		"request_limit_report_email":      settings.RequestLimitReportEMail,
		"rewrite":                         settings.Rewrite,
		"source_protocol":                 settings.SourceProtocol,
		"spdy":                            settings.Spdy,
		"ssl_client_verify":               settings.SSLClientVerify,
		"ssl_client_certificate":          settings.SSLClientCertificate,
		"ssl_client_header_verification":  settings.SSLClientHeaderVerification,
		"ssl_client_header_fingerprint":   settings.SSLClientHeaderFingerprint,
		"ssl_origin_port":                 settings.SSLOriginPort,
		"waf_enable":                      settings.WAFEnable,
		"waf_levels_enable":               settings.WAFLevelsEnable,
		"waf_policy":                      settings.WAFPolicy,
	})

	if err := d.Set("settings", settingData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

func listTagSettings(meta interface{}, tagID int) (*myrasec.Settings, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	settings, err := client.ListTagSettings(tagID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching tag settings",
			Detail:   formatError(err),
		})
	}

	return settings, diags
}

func prepareTagSettingsFilter(d interface{}) *tagSettingsFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareTagSettingsFilter", r)
		}
	}()

	return parseTagSettingsFilter(d)
}

func parseTagSettingsFilter(d interface{}) *tagSettingsFilter {
	cfg := d.([]interface{})
	f := &tagSettingsFilter{}

	m := cfg[0].(map[string]interface{})

	tagID, ok := m["tag_id"]
	if ok {
		f.tagID = tagID.(int)
	}

	return f
}

type tagSettingsFilter struct {
	tagID int
}
