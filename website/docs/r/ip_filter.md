# myrasec_ip_filter

Provides a Myra Security IP filter resource.

## Example usage

```hcl
# Create a new IP filter
resource "myrasec_ip_filter" "filter" {
  subdomain_name = "www.example.com"
  type = "BLACKLIST"
  value = "192.168.0.1"
  enabled = true
  depends_on = [
    myrasec_dns_record.www
  ]
}
```

## Argument Reference

The following arguments are supported:

* `filter_id` (Computed) ID of the IP filter.
* `created` (Computed) Date of creation.
* `modified` (Computed) Date of last modification.
* `subdomain_name` (Required) The subdomain for the IP filter.
* `type` (Required) Type of the IP filter. Valid types are: `BLACKLIST`, `WHITELIST` and `WHITELIST_REQUEST_LIMITER`.
* `value` (Required) The value of an IP filter rule can contain a single IP address or a CIDR notation. IPv4 and IPv6 are both supported. An IP filter for IPv6 can only contain a /128 subnet. An IPv4 IP filter for the `Whitelist Request Limiter` can only contain a /32 subnet.
* `enabled` (Optional) Enable or disable a filter. Default `true`.
* `expire_date` (Optional) Expire date schedules the deaktivation of the filter. If none is set, the filter will be active until manual deactivation.
* `comment` (Optional) A comment to describe this IP filter. Default `""`.