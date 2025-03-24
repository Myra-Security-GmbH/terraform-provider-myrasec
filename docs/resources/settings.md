# myrasec_settings

Provides a Myra Security settings resource.

## Example usage

```hcl
# Configure settings for a subdomain
resource "myrasec_settings" "settings" {
  subdomain_name    = "www.example.com"
  only_https        = true
  cache_enabled     = true
  limit_tls_version = [
    "TLSv1.2",
    "TLSv1.3"
  ]
}
```

## Import example
Importing existing settings requires the subdomain for the settings you want to import.
```hcl
terraform import myrasec_settings.settings www.example.com
```

## Argument Reference

The following arguments are supported:

* `subdomain_name` (**Required**) The Subdomain for the setting. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain).
* `access_log` (Optional) Activate separated access log. Default `false`.
* `antibot_post_flood` (Optional) Detection of POST floods by using a JavaScript based puzzle.. Default `false`.
* `antibot_post_flood_threshold` (Optional) This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved. Default `540`.
* `antibot_proof_of_work` (Optional) Detection of valid clients by using a JavaScript based puzzle.. Default `true`.
* `antibot_proof_of_work_threshold` (Optional) This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved. Default `1800`.
* `balancing_method` (Optional) Specifies with which method requests are balanced between upstream servers. Valid values are: `round_robin`, `ip_hash`, `least_conn` or `cookie_based`. Default `round_robin`.
* `block_not_whitelisted` (Optional) Block all IPs, which are not whitelisted. Default `false`.
* `block_tor_network` (Optional) Block traffic from the TOR network. Default `false`.
* `cache_enabled` (Optional) Turn caching on or off. Default `false`.
* `cache_revalidate` (Optional) Enable stale cache item revalidation. Default `false`.
* `cdn` (Optional) Use subdomain as Content Delivery Node (CDN). Default `false`. **Deprecated.**
* `client_max_body_size` (Optional) Sets the maximum allowed size of the client request body, specified in the “Content-Length” request header field. Maximum 5120MB. Default `10`.
* `cookie_name` (Optional) This value is required when `balancing_method` is set to `cookie_based`.
* `diffie_hellman_exchange` (Optional) The Diffie-Hellman key exchange parameter length. Valid values are: `1024`, `2048` or `4096`. Default `2048`.
* `disable_forwarded_for` (Optional) Disable the forwarded for replacement.
* `enable_origin_sni` (Optional) Enable or disable origin SNI. Default `true`.
* `enforce_cache_ttl` (Optional) Enforce using given cache TTL settings instead of origin cache information. This will set the Cache-Control header max-age to the given TTL.
* `forwarded_for_replacement` (Optional) Set your own X-Forwarded-For header. Default `X-Forwarded-For`.
* `host_header` (Optional) If set it will be used as host header, default is `$myra_host`. To reuse the default value it must be set to an empty string.
* `hsts` (Optional) HSTS Strict Transport Security (HSTS). Default `false`.
* `hsts_include_subdomains` (Optional) HSTS includeSubDomains directive. Default `false`.
* `hsts_max_age` (Optional) HSTS max-age. Default `31536000`.
* `hsts_preload` (Optional) HSTS preload directive. Default `false`.
* `http_origin_port` (Optional) Allows to set a port for communication with origin via HTTP. Default `80`.
* `ignore_nocache` (Optional) If activated, no-cache headers (Cache-Control: [private|no-store|no-cache]) will be ignored. Default `false`.
* `image_optimization` (Optional) Optimization of images. Default `true`.
* `ipv6_active` (Optional) Allow connections via IPv6 to your systems. Default `true`.
* `ip_lock` (Oprional) Prevent accidental IP address changes if activated. This setting is only available on "domain level" (general domain settings). Default `false`.
* `limit_allowed_http_method` (Optional) List of allowed HTTP methods. Valid values are `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `OPTIONS`, `PROPFIND`, `PROPPATCH`, `LOCK`, `UNLOCK`, and `PATCH`. Default allows all.
* `limit_tls_version` (Optional) List of TLS versions that will be used. Valid values are `TLSv1`, `TLSv1.1`, `TLSv1.2` and `TLSv1.3`. Default uses all.
* `log_format` (Optional) Use a different log format. Default `myra-combined-waf`.
* `monitoring_alert_threshold` (Optional) Errors per minute that must occur until a report is sent. Default `300`.
* `monitoring_contact_email` (Optional) Email addresses, to which monitoring emails should be send. Multiple addresses are separated with a space. Default `""`.
* `monitoring_send_alert` (Optional) Enables / disables the upstream error reporting. Default `false`.
* `myra_ssl_header` (Optional) Activates the X-Myra-SSL Header. Default `false`.
* `myra_ssl_certificate` (Optional) An SSL Certificate (and chain) to be used to make requests on the origin. Default `[]`
* `myra_ssl_certificate_key` (Optional) The private key(s) for the SSL Certificate(s). Default `[]`
* `next_upstream` (Optional) List of errors that mark the current upstream as "down". Valid values are `error`, `timeout`, `invalid_header`, `http_403`, `http_404`, `http_429`, `http_500`, `http_502`, `http_503`, `http_504` and `off`. Default `error`, `timeout` and `invalid_header`.
* `only_https` (Optional) Shall the origin server always be requested via HTTPS? Default `false`.
* `origin_connection_header` (Optional) Connection header. Valid values are `none`, `close` or `upgrade`. Default `none`.
* `proxy_cache_bypass` (Optional) Name of the cookie which forces Myra to deliver the response not from cache. Default `""`.
* `proxy_cache_stale` (Optional) Determines in which cases a stale cached response can be used when an error occurs. Valid values are `error`, `timeout`, `invalid_header`, `updating`, `http_500`, `http_502`, `http_503`, `http_504`, `http_403`, `http_404` and `off`. Default `updating`.
* `proxy_connect_timeout` (Optional) Timeout for establishing a connection to the upstream server. Default `60`. 
* `proxy_read_timeout` (Optional) Timeout for reading the upstream response. Default `600`.
* `request_limit_block` (Optional) Show CAPTCHA after exceeding the configured request limit. Valid values are `CAPTCHA`, `HTTP429` or `no`. Default `CAPTCHA`.
* `request_limit_level` (Optional) Sets how many requests are allowed from an IP per minute. Default `6000`.
* `request_limit_report` (Optional) If activated, an email will be send containing blocked ip addresses that exceeded the configured request limit. Default `false`.
* `request_limit_report_email` (Optional) Email addresses, to which request limit emails should be send. Multiple addresses are separated with a space. Default `""`.
* `rewrite` (Optional) Enable the JavaScript optimization. Default `false`.
* `source_protocol` (Optional) Protocol to query the origin server. Valid values are `same`, `http` or `https`. Default `same`.
* `spdy` (Optional) Activates the SPDY protocol.. Default `true`.
* `ssl_client_verify` (Optional) Enables verification of client certificates. Valid values are `of`, `on` or `optional`. Default `off`.
* `ssl_client_certificate` (Optional) Specifies a file with trusted CA certificates in the PEM format used to verify client certificates.
* `ssl_client_header_verification` (Optional) The name of the header, which contains the ssl verification status.
* `ssl_client_header_fingerprint` (Optional) Contains the fingerprint of the certificate, the client used to authenticate itself.
* `ssl_origin_port` (Optional) Allows to set a port for communication with origin via SSL. Default `443`.
* `waf_enable` (Optional) Enables / disables the Web Application Firewall. Default `false`.
* `waf_levels_enable` (Optional) Level of applied WAF rules. Valid values are `waf_tag`, `waf_domain` and `waf_subdomain`. Default `waf_tag`, `waf_domain` and `waf_subdomain`.
* `waf_policy` (Optional) Default policy for the Web Application Firewall in case of rule error. Valid values are `allow` or `block`. Default `allow`.
