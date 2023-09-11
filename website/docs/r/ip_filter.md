# myrasec_ip_filter

Provides a Myra Security IP filter resource.

You can create 3 different types of IP filters:
* BLACKLIST
* WHITELIST
* WHITELIST_REQUEST_LIMITER

## Example usage

```hcl
# Create a new IP filter
resource "myrasec_ip_filter" "filter" {
  subdomain_name = "www.example.com"
  type           = "BLACKLIST"
  value          = "192.168.0.1/32"
  enabled        = true
}
```

## Import example
Importing an existing IP filter requires the subdomain and the ID of the IP filter you want to import.
```hcl
terraform import myrasec_ip_filter.filter www.example.com:0000000
```

## Argument Reference

The following arguments are supported:

* `filter_id` (*Computed*) ID of the IP filter.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `subdomain_name` (**Required**) The subdomain for the IP filter. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain).
* `type` (**Required**) Type of the IP filter. Valid types are: `BLACKLIST`, `WHITELIST` and `WHITELIST_REQUEST_LIMITER`.
* `value` (**Required**) The value of an IP filter rule can contain a single IP address or a CIDR notation. IPv4 and IPv6 are both supported. An IP filter for IPv6 can only contain a /128 subnet. An IPv4 IP filter for the `Whitelist Request Limiter` can only contain a /32 subnet.
* `enabled` (Optional) Enable or disable a filter. Default `true`.
* `expire_date` (Optional) Expiry date schedules the deactivation of the filter. If none is set, the filter will be active until manual deactivation.
* `comment` (Optional) A comment to describe this IP filter. Default `""`.