# myrasec_tag_settings

Provides a Myra Security tag settings resource.

## Example usage

```hcl
# Configure settings for a tag
resource "myrasec_tag_settings" "example_tag_settings" {
  tag_id = myrasec_tag.example_tag.id
  only_https = true
  cache_enabled = true
}
```

## Argument Reference

The following arguments are supported:

* `tag_id` (Required) The tag ID for the setting. You can use the ID of the tag `0000` or the reference to the tag, if it is also managed by terraform `myrasec_tag.example_tag.id`
* `access_log` (Optional) Activate separated access log. Default `false`.
* `antibot_post_flood` (Optional) Detection of POST floods by using a JavaScript based puzzle.. Default `false`.
* `antibot_post_flood_threshold` (Optional) This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved. Default `540`.
* `antibot_proof_of_work` (Optional) Detection of valid clients by using a JavaScript based puzzle.. Default `true`.
* `antibot_proof_of_work_threshold` (Optional) This parameter determines the frequency how often the puzzle has to be solved. The higher the value the less likely the puzzle needs to be solved. Default `1800`.
* `balancing_method` (Optional) Specifies with which method requests are balanced between upstream servers. Valid values are: `round_robin`, `ip_hash` or `least_conn`. Default `round_robin`.
* `block_not_whitelisted` (Optional) Block all IPs, which are not whitelisted. Default `false`.
* `block_tor_network` (Optional) Block traffic from the TOR network. Default `false`.
* `cache_enabled` (Optional) Turn caching on or off. Default `false`.
* `cache_revalidate` (Optional) Enable stale cache item revalidation. Default `false`.
* `cdn` (Optional) Use subdomain as Content Delivery Node (CDN). Default `false`.
* `client_max_body_size` (Optional) Sets the maximum allowed size of the client request body, specified in the “Content-Length” request header field. Maximum 250MB. Default `10`.
* `diffie_hellman_exchange` (Optional) The Diffie-Hellman key exchange parameter length. Valid values are: `1024` or `2048`. Default `2048`.
* `enable_origin_sni` (Optional) Enable or disable origin SNI. Default `true`.
* `forwarded_for_replacement` (Optional) Set your own X-Forwarded-For header. Default `X-Forwarded-For`.
* `hsts` (Optional) HSTS Strict Transport Security (HSTS). Default `false`.
* `hsts_include_subdomains` (Optional) HSTS includeSubDomains directive. Default `false`.
* `hsts_max_age` (Optional) HSTS max-age. Default `31536000`.
* `hsts_preload` (Optional) HSTS preload directive. Default `false`.
* `http_origin_port` (Optional) Allows to set a port for communication with origin via HTTP. Default `80`.
* `ignore_nocache` (Optional) If activated, no-cache headers (Cache-Control: [private|no-store|no-cache]) will be ignored. Default `false`.
* `image_optimization` (Optional) Optimization of images. Default `true`.
* `ipv6_active` (Optional) Allow connections via IPv6 to your systems. Default `true`.
* `log_format` (Optional) Use a different log format. Default `myra-combined-waf`.
* `monitoring_alert_threshold` (Optional) Errors per minute that must occur until a report is sent. Default `300`.
* `monitoring_send_alert` (Optional) Enables / disables the upstream error reporting. Default `false`.
* `myra_ssl_header` (Optional) Activates the X-Myra-SSL Header. Default `false`.
* `only_https` (Optional) Shall the origin server always be requested via HTTPS? Default `false`.
* `origin_connection_header` (Optional) Connection header. Valid values are `none`, `close` or `upgrade`. Default `none`.
* `proxy_connect_timeout` (Optional) Timeout for establishing a connection to the upstream server. Default `60`. 
* `proxy_read_timeout` (Optional) Timeout for reading the upstream response. Default `600`.
* `request_limit_block` (Optional) Show CAPTCHA after exceeding the configured request limit. Valid values are `CAPTCHA`, `HTTP429` or `no`. Default `CAPTCHA`.
* `request_limit_level` (Optional) Sets how many requests are allowed from an IP per minute. Default `6000`.
* `request_limit_report` (Optional) If activated, an email will be send containing blocked ip addresses that exceeded the configured request limit. Default `false`.
* `rewrite` (Optional) Enable the JavaScript optimization. Default `false`.
* `source_protocol` (Optional) Protocol to query the origin server. Valid values are `same`, `http` or `https`. Default `same`.
* `spdy` (Optional) Activates the SPDY protocol.. Default `true`.
* `ssl_origin_port` (Optional) Allows to set a port for communication with origin via SSL. Default `443`.
* `waf_enable` (Optional) Enables / disables the Web Application Firewall. Default `false`.
* `waf_policy` (Optional) Default policy for the Web Application Firewall in case of rule error. Valid values are `allow` or `block`. Default `allow`.
