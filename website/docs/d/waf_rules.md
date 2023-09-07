# myrasec_waf_rules

Use this data source to look up WAF rules.

## Example usage

```hcl
data "myrasec_waf_rules" "www" {
    filter {
        subdomain_name = "www.example.com"
    }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) Filter the WAF actions.

### filter
* `subdomain_name` (**Required**) The action type to filter for. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain).
* `search` (Optional) A search string to filter the WAF rules.

## Attributes Reference
* `waf_rules` A list of WAF rules.

### rules
* `id` The ID of the WAF action.
* `created` Date of creation.
* `modified` Date of last modification.
* `rule_type` The type of the rule.  
* `subdomain_name` The subdomain for the rule.  
* `name` The rule name identifies each rule.
* `direction`  Phase specifies the condition under which a rule applies. Pre-origin means before your server (request), post-origin is past your server (response). Valid values are `in` for request or `out` for response.  
* `description` Your notes on this rule.
* `log_identifier` A comment to identify the matching rule in the access log.
* `expire_date` Expire date schedules the deaktivation of the WAF rule.
* `sort` The order in which the rules take action.
* `process_next` After a rule has been applied, the rule chain will be executed as determined.
* `enabled` Define wether this rule is enabled or not.
* `conditions` The conditions of a rule have to be true for a rule to be executed.
* `actions` Refers to actions that are executed when all conditions of a rule are true.
