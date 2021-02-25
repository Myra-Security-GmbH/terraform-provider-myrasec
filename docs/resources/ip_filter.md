# myrasec_ip_filter

Provides a Myra Security IP filter resource.

## Example Usage

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

* `subdomain_name` (Required) The Subdomain for the IP filter.
* `filter_id` (computed) ID of the IP filter.
* `created` (computed) Date of creation.
* `modified` (computed) Date of last modification.
* `type` (Required) Type of the IP filter. Valid types are: `BLACKLIST`, `WHITELIST` and `WHITELIST_REQUEST_LIMITER`.
* `value` (Required) The IP you want to whitelist or blacklist. By using CIDR notation on IPv4 IPs, you are able to define whole subnets.
* `enabled` (Optional) Enable or disable a filter. Default `true`.
* `expire_date` (Optional) Expire date schedules the deaktivation of the filter. If none is set, the filter will be active until manual deactivation.
* `comment` (Optional) A comment to describe this IP filter. Default `""`.