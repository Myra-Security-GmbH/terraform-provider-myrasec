# myrasec_domains

Use this data source to look up Domain records.

## Example usage

```hcl
# Look for the "example.com" domain
data "myrasec_domains" "example" {
    filter {
        name  = "example.com"
        id    = 1
        match = "example"
    }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) One or more values to filter the domains.

### filter
* `id` (Optional) The ID of the domain filter for.
* `name` (Optional) The domain name to filter for.
* `match` (Optional) A regex to filter domains. The regex is applied on the domain name. NOTE: If you specify a match/regex, the `name` filter has no effect!

## Attributes Reference
* `domains` A list of domains.

### domains
* `id` The ID of the domain.
* `created` Date of creation.
* `modified` Date of last modification.
* `name` The Domain name.
* `auto_update` Auto update flag from the domain.
