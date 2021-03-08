# myrasec_domains

Use this data source to look up Domain records.

## Example usage

```hcl
# Look for the "example.com" domain
data "myrasec_domains" "example" {
    filter {
        name = "example.com"
    }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (Required) One or more values to filter the domains.

### filter
* `id` (Optional) The ID of the domain filter for.
* `name` (Optional) The domain name to filter for.

## Attributes Reference
* `domains` A list of domains.

### domains
* `id` The ID of the domain.
* `created` Date of creation.
* `modified` Date of last modification.
* `name` The Domain name.
* `auto_update` Auto update flag from the domain.
* `paused` Shows if Myra is paused for this domain.
* `paused_until` Date until Myra will be automatically reactivated.
