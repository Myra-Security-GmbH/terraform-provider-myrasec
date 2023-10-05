# Variables
Here you see a list of variables you can use for your myrasec terraform project.

The variable names are constructed as "`resourceName`**-**`attributeName`**.**`valueName`"

Add this as `myrasec_variables.tf` to your terraform project:
```hcl
variable "myrasec_errorpage-error_code" {
  default = {
    "bad_request"           = 400
    "method_not_allowed"    = 405
    "too_many_requests"     = 429
    "internal_server_error" = 500
    "bad_gateway"           = 502
    "service_unavailable"   = 503
    "gateway_timeout"       = 504
    "blocked_request"       = 9999
  }
}

variable "myrasec_cache_setting-type" {
  default = {
    "prefix" = "prefix"
    "suffix" = "suffix"
    "exact"  = "exact"
  }
}

variable "myrasec_redirect-matching_type" {
  default = {
    "prefix" = "prefix"
    "suffix" = "suffix"
    "exact"  = "exact"
  }
}

variable "myrasec_redirect-type" {
  default = {
    "permanent" = "permanent"
    "redirect"  = "redirect"
    "HTTP-301"  = "permanent"
    "HTTP-302"  = "redirect"
  }
}

variable "myrasec_dns_record-record_type" {
  default = {
    "A"     = "A"
    "AAAA"  = "AAAA"
    "MX"    = "MX"
    "CNAME" = "CNAME"
    "TXT"   = "TXT"
    "NS"    = "NS"
    "SRV"   = "SRV"
    "CAA"   = "CAA"
    "PTR"   = "PTR"
  }
}

variable "myrasec_dns_record-ttl" {
  default = {
    300   = 300
    600   = 600
    900   = 900
    1800  = 1800
    3600  = 3600
    7200  = 7200
    18000 = 18000
    43200 = 43200
    86400 = 86400
  }
}

variable "myrasec_ip_filter-type" {
  default = {
    "BLACKLIST"                 = "BLACKLIST"
    "WHITELIST"                 = "WHITELIST"
    "WHITELIST_REQUEST_LIMITER" = "WHITELIST_REQUEST_LIMITER"
  }
}

variable "myrasec_settings-balancing_method" {
  default = {
    "round_robin"  = "round_robin"
    "ip_hash"      = "ip_hash"
    "least_conn"   = "least_conn"
    "cookie_based" = "cookie_based"
  }
}

variable "myrasec_settings-diffie_hellman_exchange" {
  default = {
    1024 = 1024
    2048 = 2048
    4096 = 4096
  }
}

variable "myrasec_settings-next_upstream" {
  default = {
    "error"          = "error"
    "timeout"        = "timeout",
    "invalid_header" = "invalid_header",
    "http_403"       = "http_403"
    "http_404"       = "http_404"
    "http_429"       = "http_429"
    "http_500"       = "http_500"
    "http_502"       = "http_502"
    "http_503"       = "http_503"
    "http_504"       = "http_504"
    "off"            = "off"
  }
}

variable "myrasec_settings-origin_connection_header" {
  default = {
    "none"    = "none"
    "close"   = "close"
    "upgrade" = "upgrade"
  }
}

variable "myrasec_settings-proxy_cache_stale" {
  default = {
    "error"   = "error"
    "timeout" = "timeout",
  }
}

variable "myrasec_settings-proxy_connect_timeout" {
  default = {
    1  = 1
    2  = 2
    3  = 3
    5  = 5
    10 = 10
    15 = 15
    30 = 30
    45 = 45
    60 = 60
  }
}

variable "myrasec_settings-proxy_read_timeout" {
  default = {
    1    = 1
    2    = 2
    5    = 5
    10   = 10
    15   = 15
    30   = 30
    45   = 45
    60   = 60
    120  = 120
    180  = 180
    300  = 300
    600  = 600
    1200 = 1200
    2400 = 2400
  }
}

variable "myrasec_settings-request_limit_block" {
  default = {
    "CAPTCHA" = "CAPTCHA"
    "HTTP429" = "HTTP429"
    "NO"      = "no"
  }
}

variable "myrasec_settings-source_protocol" {
  default = {
    "same"  = "same"
    "http"  = "http"
    "https" = "https"
  }
}

variable "myrasec_settings-waf_levels_enable" {
  default = {
    "waf_tag"       = "waf_tag"
    "waf_domain"    = "waf_domain"
    "waf_subdomain" = "waf_subdomain"
  }
}

variable "myrasec_settings-waf_policy" {
  default = {
    "allow" = "allow"
    "block" = "block"
  }
}

variable "myrasec_tag-type" {
  default = {
    "CACHE"      = "CACHE"
    "CONFIG"     = "CONFIG"
    "RATE_LIMIT" = "RATE_LIMIT"
    "WAF"        = "WAF"
  }
}

variable "myrasec_tag-assignments-type" {
  default = {
    "DOMAIN"    = "DOMAIN"
    "SUBDOMAIN" = "SUBDOMAIN"
  }
}

variable "myrasec_waf_rule-direction" {
  default = {
    "in"       = "in"
    "out"      = "out"
    "request"  = "in"
    "response" = "out"
  }
}

variable "myrasec_waf_rule-condition-name-in" {
  default = {
    "custom_header"   = "custom_header"
    "host"            = "host"
    "user_agent"      = "user_agent"
    "accept"          = "accept"
    "accept_encoding" = "accept_encoding"
    "cookie"          = "cookie"
    "url"             = "url"
    "method"          = "method"
    "arg"             = "arg"
    "postarg"         = "postarg"
    "querystring"     = "querystring"
    "fingerprint"     = "fingerprint"
    "remote_addr"     = "remote_addr"
    "score"           = "score"
  }
}

variable "myrasec_waf_rule-condition-matching_type-default" {
  default = {
    "REGEX"  = "REGEX"
    "IREGEX" = "IREGEX"
    "EXACT"  = "EXACT"
    "PREFIX" = "PREFIX"
    "SUFFIX" = "SUFFIX"
  }
}

variable "myrasec_waf_rule-condition-matching_type-score" {
  default = {
    "GREATER_THAN" = "GREATER_THAN"
    "LESS_THAN"    = "LESS_THAN"
    "EQUALS"       = "EQUALS"
  }
}

variable "myrasec_waf_rule-condition-name-out" {
  default = {
    "custom_header" = "custom_header"
    "content_type"  = "content_type"
    "set_cookie"    = "set_cookie"
  }
}

variable "myrasec_waf_rule-action-type" {
  default = {
    "modify_header"     = "modify_header"
    "add_header"        = "add_header"
    "remove_header"     = "remove_header"
    "change_upstream"   = "change_upstream"
    "origin_rate_limit" = "origin_rate_limit"
    "score"             = "score"
    "uri_subst"         = "uri_subst"
    "set_http_status"   = "set_http_status"
  }
}

variable "myrasec_waf_rule-action-set_http_status" {
  default = {
    300 = 300
    302 = 302
    400 = 400
  }
}

variable "myrasec_ip_ranges-type" {
  default = {
    "ipv4" = "ipv4"
    "ipv6" = "ipv6"
  }
}

variable "myrasec_ratelimit-value" {
  default = {
    "very_low"  = 4000
    "low"       = 2000
    "normal"    = 1000
    "high"      = 500
    "very_high" = 100
    "extreme"   = 60
    "disabled"  = 0
  }
}
```