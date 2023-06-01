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
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Not selected HTTP methods will be blocked.",
			},
			"limit_tls_version": {
				Type:     schema.TypeSet,
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
				Type:     schema.TypeSet,
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
				Type:     schema.TypeSet,
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
				Type:     schema.TypeSet,
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
			"available_attributes": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
		CustomizeDiff: resourceCustomizeDiff,
	}
}

func resourceCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
	availableAttributes := []string{}

	resource := resourceMyrasecSettings()
	for name, attr := range resource.Schema {
		if attr.Type == schema.TypeBool {
			isNullValue := d.GetRawConfig().GetAttr(name).IsNull()

			if !isNullValue {
				availableAttributes = append(availableAttributes, name)
			}
		}
	}

	d.SetNew("available_attributes", availableAttributes)

	return nil
}

// resourceMyrasecSettingsCreate ...
func resourceMyrasecSettingsCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	settings, err := buildSettings(d, false)
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

	settings, err := client.ListSettingsFull(domainID, subDomainName, nil)
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

	settings, err := buildSettings(d, false)
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

	return resourceMyrasecSettingsRead(ctx, d, meta)
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

	settings, err := buildSettings(d, true)
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
			Summary:  "Error deleting settings",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// buildSettings ...
func buildSettings(d *schema.ResourceData, clean bool) (map[string]interface{}, error) {
	settingsMap := make(map[string]interface{})

	resource := resourceMyrasecSettings()
	for name, attr := range resource.Schema {
		if name == "domain_id" || name == "subdomain_name" || name == "available_attributes" {
			continue
		}
		if name == "proxy_host_header" {
			name = "host_header"
		}
		value, ok := d.GetOk(name)
		if attr.Type == schema.TypeBool {
			ok = !d.GetRawConfig().GetAttr(name).IsNull()
		}
		if ok && !clean {
			switch attr.Type {
			case schema.TypeBool:
				settingsMap[name] = value.(bool)
			case schema.TypeInt:
				settingsMap[name] = value.(int)
			case schema.TypeString:
				settingsMap[name] = value.(string)
			case schema.TypeList:
				settingsList := []string{}
				for _, item := range value.([]interface{}) {
					settingsList = append(settingsList, item.(string))
				}
				settingsMap[name] = settingsList
			case schema.TypeSet:
				settingsList := []string{}
				for _, v := range value.(*schema.Set).List() {
					log.Println(v)
					settingsList = append(settingsList, v.(string))
				}
				settingsMap[name] = settingsList
			}
		} else {
			settingsMap[name] = nil
		}
	}

	return settingsMap, nil
}

// setSettingsData ...
func setSettingsData(d *schema.ResourceData, settingsData interface{}, subDomainName string, domainID int) {
	d.Set("subdomain_name", subDomainName)
	d.Set("domain_id", domainID)

	allSettings, _ := settingsData.(*map[string]interface{})
	domainSettings := (*allSettings)["domain"]

	availableAttribtues := []string{}
	for k, v := range domainSettings.(map[string]interface{}) {
		d.Set(k, v)
		if _, ok := v.(bool); ok {
			availableAttribtues = append(availableAttribtues, k)
		}
	}
	d.Set("available_attributes", availableAttribtues)
}
