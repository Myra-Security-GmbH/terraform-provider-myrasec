# myrasec_waf_conditions

Use this data source to look up WAF conditions.

## Example usage

```hcl
# Look for the "utl" WAF condition
data "myrasec_waf_conditions" "url" {
    filter {
        name = "url"
    }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) Filter the WAF conditions.

### filter
* `name` (Optional) The condition name to filter for.

## Attributes Reference
* `conditions` A list of WAF conditions.

### conditions
* `id` The ID of the WAF condition.
* `created` Date of creation.
* `modified` Date of last modification.
* `name` The name of the WAF condition.
* `available_phases` The allowed phases where this condition can be used. `1`: Request|in, `2`: Response|out, `3`: both