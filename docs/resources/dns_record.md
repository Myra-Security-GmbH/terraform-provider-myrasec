# myrasec_dns_record

Provides a Myra Security DNS record resource.

## Example Usage

```hcl
# Create a DNS record
resource "myrasec_dns_record" "www" {
    domain_name = "example.com"
    name = "www"
    record_type = "A"
    value = "192.168.0.1"
    ttl = 300
    active = true
    enabled = true
    depends_on = [ 
        myrasec_domain.example
    ]
}
```

## Argument Reference

The following arguments are supported:

* `domain_name` (Required) The Domain for the DNS record.
* `record_id` (computed) ID of the DNS record.
* `created` (computed) Date of creation.
* `modified` (computed) Date of last modification.
* `record_type` (Required) A record type to identify the type of a record. Valid types are: `A`, `AAAA`, `MX`, `CNAME`, `TXT`, `NS`, `SRV` and `CAA`.
* `name` (Required) Subdomain name of a DNS record.
* `value` (Required) Depends on the record type. Typically an IPv4/6 address or a domain entry.
* `ttl` (Required) Time to live.
* `alternative_cname` (Optional) The alternative CNAME that points to the record.
* `active` (Optional) Define wether this subdomain should be protected by Myra or not. Default `true`.
* `enabled` (Optional) Define wether this DNS record is enabled or not. Default `true`.
* `priority` (Optional) Priority of MX records.
* `port` (Optional) Port for SRV records.
* `comment` (Optional) A comment to describe this DNS record. Default `""`.