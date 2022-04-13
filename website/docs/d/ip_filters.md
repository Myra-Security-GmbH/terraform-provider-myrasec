# myrasec_ip_filters

Use this data source to look up IP filters.

## Example usage

```hcl
# Look for a ip filters
data "myrasec_ip_filters" "ipfilter" {
  filter {
    subdomain_name = "www.example.com"
    search = "127.0.0.1"
    type = "WHITELIST"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (Required) One or more values to filter the IP filters.

### filter
* `subdomain_name` (Required) The subdomain name from the rate limit. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain) or the `ALL:example.com` annotation.
* `search` (Optional) A search string to filter the IP filters. Filers on the `value` field.
* `type` (Optional) Specify the filter type.


## Attributes Reference
* `ipfilters` A list of IP filters.

### ipfilters
* `id` The ID of the IP filter.
* `created` Date of creation.
* `modified` Date of last modification.
* `type` Type of the IP filter.
* `value` The IP you want to whitelist or blacklist.
* `enabled` Enable or disable a filter.
* `expire_date` Expire date schedules the deaktivation of the filter.
* `comment` A comment to describe this IP filter.