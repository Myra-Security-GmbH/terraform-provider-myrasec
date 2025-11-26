package myrasec

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const (
	ClientMaxBodySize = 5120
)

var diffieHellmanExchangeValues = []int{1024, 2048, 4096}
var proxyReadTimeoutValues = []int{1, 2, 5, 10, 15, 30, 45, 60, 120, 180, 300, 600, 1200, 2400, 3600, 7200}

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
				StateFunc: func(i any) string {
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
				ValidateFunc: validation.StringInSlice([]string{"round_robin", "ip_hash", "least_conn", "cookie_based"}, false),
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
				Deprecated:  "This setting has no effect anymore.",
				Description: "Use subdomain as Content Delivery Node (CDN).",
			},
			"client_max_body_size": {
				Type:         schema.TypeInt,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, ClientMaxBodySize),
				Description:  fmt.Sprintf("Sets the maximum allowed size of the client request body, specified in the “Content-Length” request header field. Maximum %d MB.", ClientMaxBodySize),
			},
			"cookie_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the cookie name when balancing_method is cookie_based",
			},
			"diffie_hellman_exchange": {
				Type:         schema.TypeInt,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.IntInSlice(diffieHellmanExchangeValues),
				Description:  "The Diffie-Hellman key exchange parameter length.",
			},
			"disable_forwarded_for": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Disable the forwarded for replacement.",
			},
			"enable_origin_sni": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable or disable origin SNI.",
			},
			"enforce_cache_ttl": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enforce using given cache TTL settings instead of origin cache information. This will set the Cache-Control header max-age to the given TTL.",
			},
			"forwarded_for_replacement": {
				Type:     schema.TypeString,
				Required: false,
				Optional: true,
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					disable, ok := d.GetOk("disable_forwarded_for")
					if !ok {
						return false
					}
					if disable.(bool) {
						return true
					}
					return false
				},
				Description: "Set your own X-Forwarded-For header.",
			},
			"host_header": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Proxy host header",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old == "$myra_host" && new == ""
				},
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
			"ip_lock": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Prevent accidental IP address changes if activated. This setting is only available on 'domain level' (general domain settings).",
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
			"myra_ssl_certificate": {
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Authentication to the origin. An SSL Certificate (and chain) to be used to make requests on the origin.",
			},
			"myra_ssl_certificate_key": {
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "The private key for the SSL Certificate",
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
				Type:         schema.TypeInt,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.IntInSlice([]int{1, 2, 3, 5, 10, 15, 30, 45, 60}),
				Description:  "Timeout for establishing a connection to the upstream server.",
			},
			"proxy_host_header": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Proxy host header",
				Deprecated:  "Please use `host_header` instead",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old == "$myra_host" && new == ""
				},
			},
			"proxy_read_timeout": {
				Type:         schema.TypeInt,
				Required:     false,
				Optional:     true,
				ValidateFunc: validation.IntInSlice(proxyReadTimeoutValues),
				Description:  "Timeout for reading the upstream response.",
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
			"ssl_client_verify": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enables verification of client certificates.",
			},
			"ssl_client_certificate": {
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies a file with trusted CA certificates in the PEM format used to verify client certificates.",
			},
			"ssl_client_header_verification": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The name of the header, which contains the ssl verification status.",
			},
			"ssl_client_header_fingerprint": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Contains the fingerprint of the certificate, the client used to authenticate itself.",
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
		CustomizeDiff: resourceCustomizeDiffSettings,
	}
}

// resourceCustomizeDiffSettings
func resourceCustomizeDiffSettings(ctx context.Context, d *schema.ResourceDiff, m any) error {
	availableAttributes := []string{}
	resource := resourceMyrasecSettings()
	for name, attr := range resource.Schema {
		if name == "domain_id" || name == "subdomain_name" || name == "available_attributes" {
			continue
		}

		isNullValue := isNullValue(attr, d, name)
		if name == "forwarded_for_replacement" {
			disable, ok := d.GetOk("disable_forwarded_for")
			if ok && disable.(bool) {
				isNullValue = true
			}
		}
		if name == "proxy_host_header" {
			name = "host_header"
		}
		if !isNullValue {
			availableAttributes = append(availableAttributes, name)
		}
	}
	d.SetNew("available_attributes", availableAttributes)

	return validateCookieBasedName(d)
}

func isNullValue(t *schema.Schema, d *schema.ResourceDiff, name string) bool {
	isNullValue := false
	switch t.Type {
	case schema.TypeBool:
		isNullValue = d.GetRawConfig().GetAttr(name).IsNull()
	case schema.TypeInt:
		_, ok := d.GetOk(name)
		if !ok {
			isNullValue = d.GetRawConfig().GetAttr(name).IsNull()
		}
	case schema.TypeSet:
		size := len(d.Get(name).(*schema.Set).List())
		isNullValue = size == 0
	case schema.TypeList:
		size := len(d.Get(name).([]any))
		isNullValue = size == 0
	case schema.TypeString:
		value := d.Get(name)
		isNullValue = value == nil || value == ""
	}
	return isNullValue
}

// resourceMyrasecSettingsCreate ...
func resourceMyrasecSettingsCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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
func resourceMyrasecSettingsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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
	clientMaxBodySize := d.Get("client_max_body_size")

	if clientMaxBodySize.(int) > ClientMaxBodySize {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "client_max_body_size for " + subDomainName,
			Detail:   fmt.Sprintf("Value of this setting was set by Myra support to %d MB will now be changed.", clientMaxBodySize.(int)),
		})
	}

	return diags
}

// resourceMyrasecSettingsUpdate ...
func resourceMyrasecSettingsUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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
func resourceMyrasecSettingsDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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
func buildSettings(d *schema.ResourceData, clean bool) (map[string]any, error) {
	settingsMap := make(map[string]any)

	resource := resourceMyrasecSettings()
	for name, attr := range resource.Schema {
		if name == "domain_id" || name == "subdomain_name" || name == "available_attributes" {
			continue
		}
		value, ok := d.GetOk(name)
		if !clean {
			ok = !d.GetRawConfig().GetAttr(name).IsNull()
		}
		if name == "proxy_host_header" {
			if _, ok := d.GetOk("host_header"); ok {
				name = "host_header"
			} else {
				continue
			}
		}
		if name == "forwarded_for_replacement" {
			disable := d.Get("disable_forwarded_for")
			if disable.(bool) {
				ok = false
			}
		}
		if ok && !clean {
			switch attr.Type {
			case schema.TypeBool:
				settingsMap[name] = value.(bool)
			case schema.TypeInt:
				settingsMap[name] = value.(int)
			case schema.TypeString:
				if value.(string) != "" {
					settingsMap[name] = value.(string)
				} else {
					settingsMap[name] = nil
				}
			case schema.TypeList:
				settingsList := []string{}
				for _, item := range value.([]any) {
					settingsList = append(settingsList, item.(string))
				}
				settingsMap[name] = settingsList
			case schema.TypeSet:
				settingsList := []string{}
				for _, v := range value.(*schema.Set).List() {
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
func setSettingsData(d *schema.ResourceData, settingsData any, subDomainName string, domainID int) {
	d.Set("subdomain_name", subDomainName)
	d.Set("domain_id", domainID)

	resource := resourceMyrasecSettings().Schema

	// reset attributes befor setting them
	for name := range resource {
		if name == "domain_id" || name == "subdomain_name" || name == "available_attributes" {
			continue
		}
		d.Set(name, nil)
	}

	allSettings, _ := settingsData.(*map[string]any)
	domainSettings := (*allSettings)["domain"]

	availableAttributes := []string{}
	mapSettings, ok := domainSettings.(map[string]any)
	if ok {
		for k, v := range mapSettings {
			if k == "proxy_host_header" && mapSettings["host_header"] == nil {
				k = "host_header"
			}
			if _, ok := resource[k]; !ok {
				continue
			}
			d.Set(k, v)
			doAppend := appendAvailableAttributes(v, k, resource)
			if doAppend {
				availableAttributes = append(availableAttributes, k)
			}
		}
	}
	d.Set("available_attributes", availableAttributes)

	method := d.Get("balancing_method")
	if method != "cookie_based" {
		d.Set("cookie_name", "")
	}
}

func appendAvailableAttributes(v any, k string, resource map[string]*schema.Schema) bool {
	append := false

	if _, ok := resource[k]; !ok {
		return append
	}
	if _, ok := v.(bool); ok {
		if _, ok := resource[k]; ok {
			append = true
		}
	}
	if _, ok := v.(int); ok {
		append = true
	}
	if _, ok := v.(float32); ok {
		append = true
	}
	if _, ok := v.(float64); ok {
		append = true
	}
	if _, ok := v.(string); ok && v != "" {
		append = true
	}
	if _, ok := v.([]any); ok {
		append = true
	}

	return append
}

func validateCookieBasedName(d *schema.ResourceDiff) error {
	method := d.Get("balancing_method")
	cookie := d.Get("cookie_name")
	if method == "cookie_based" {
		if cookie == "" {
			return fmt.Errorf("cookie_name is required when balancing_method is cookie_based")
		}
		re := regexp.MustCompile("^[a-zA-Z0-9]*$")
		if !re.MatchString(cookie.(string)) {
			return fmt.Errorf("cookie_name can only contain alphanumeric characters")
		}
	} else if cookie != "" {
		return fmt.Errorf("cookie_name is only allowed when balancing_method is cookie_based")
	}

	return nil
}
