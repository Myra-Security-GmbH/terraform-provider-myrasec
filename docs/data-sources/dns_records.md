# myrasec_dns_records

Use this data source to look up DNS records.

## Example usage

```hcl
# Look for the "www.example.com" dns record
data "myrasec_dns_records" "records" {
  filter {
    domain_name = "example.com"
    name        = "www"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) One or more values to filter the dns records.

### filter
* `domain_name` (**Required**) The domain name to filter the DNS records.
* `name` (Optional) The record name to filter for.
* `match` (Optional) A regex to filter DNS records. The regex is applied on the name field. NOTE: If you specify a match/regex, the `name` filter has no effect!

## Attributes Reference
* `records` A list of DNS records.

### records
* `id` ID of the DNS record.
* `created` Date of creation.
* `modified` Date of last modification.
* `record_type` A record type to identify the type of a record.
* `name` Subdomain name of a DNS record.
* `value` Depends on the record type. Typically an IPv4/6 address or a domain entry.
* `ttl` Time to live.
* `alternative_cname` The alternative CNAME that points to the record.
* `active` Define wether this subdomain should be protected by Myra or not.
* `enabled` Define wether this DNS record is enabled or not.
* `priority` Priority of MX records.
* `port` Port for SRV records.
* `comment` A comment to describe this DNS record.
* `upstream_options` Loadbalancing settings.
* `upstream_options.upstream_id` ID of the upstream settings.
* `upstream_options.created` Date of creation.
* `upstream_options.modified` Date of last modification.
* `upstream_options.backup` Marks the server as a backup server.
* `upstream_options.down` Marks the server as unavailable.
* `upstream_options.fail_timeout` Double usage: 1. Time period in which the max_fails must occur until the upstream is deactivated. 2. Time period the upstream is deactivated until it is reactivated. The time during which the specified number of unsuccessful attempts "Max fails" to communicate with the server should happen to consider the server unavailable. Also the period of time the server will be considered unavailable. 
* `upstream_options.max_fails` The number of unsuccessful attempts to communicate with the server that should happen in the duration set by "Fail timeout" to consider the server unavailable. Also the server is considered unavailable for the duration set by "Fail timeout". By default, the number of unsuccessful attempts is set to 1. Setting the value to zero disables the accounting of attempts. What is considered an unsuccessful attempt is defined by the "Next upstream error handling".
* `upstream_options.weight` Weight defines the count of requests a upstream handles before the next upstream is selected.
