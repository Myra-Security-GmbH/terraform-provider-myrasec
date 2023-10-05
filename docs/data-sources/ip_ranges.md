# myrasec_ip_ranges

Use this data source to look up IP ranges.

## Example usage

```hcl
# Look for ip ranges
data "myrasec_ip_ranges" "ipranges" {
    filter {
        search = "192.168.1."
        type   = "ipv4"
    }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (Optional)) One or more values to filter the IP ranges.

### filter
* `search` (Optional) A search string to filter the IP ranges.
* `type` (Optional) Filter for IP ranges of the given IP version. Possible values are `ipv4` or `ipv6`.

## Attributes Reference
* `ipranges` A list of IP ranges.

### ipranges
* `id` The ID of the redirect.
* `created` Date of creation.
* `modified` Date of last modification.
* `network` The IP range network (CIDR).
* `enabled` Enable or disable a filter.
* `valid_from` Valid from date.
* `valid_to` Valid to date.
* `comment` A comment to describe this IP range.