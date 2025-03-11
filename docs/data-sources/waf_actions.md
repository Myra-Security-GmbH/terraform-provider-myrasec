# myrasec_waf_actions

Use this data source to look up WAF actions.

## Example usage

```hcl
# Look for the "change_upstream" WAF action
data "myrasec_waf_actions" "upstream" {
    filter {
        type = "change_upstream"
    }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) Filter the WAF actions.

### filter
* `type` (Optional) The action type to filter for.

## Attributes Reference
* `waf_actions` A list of WAF actions.

### actions
* `created` Date of creation.
* `modified` Date of last modification.
* `name` The name of the WAF action.
* `type` The type of the WAF action.
* `available_phases` The allowed phases where this action can be used. `1`: Request|in, `2`: Response|out, `3`: both