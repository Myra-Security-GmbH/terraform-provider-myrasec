# myrasec_tag_waf_rules

Use this data source to look up tag WAF rules.

## Example usage

```hcl
data "myrasec_tag_waf_rules" "example_tag_waf_rule" {
    filter {
        tag_id = myrasec_tag.example_tag.id
    }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (Required) Filter the WAF rules.

### filter
* `tag_id` (Required) The action type to filter for.
* `search` (Optional) A search string to filter the WAF rules.

## Attributes Reference
* `waf_rules` A list of WAF rules.

### rules
* `id` The ID of the WAF action.
* `created` Date of creation.
* `modified` Date of last modification.


* `rule_type` The type of the rule.
* `tag_id` The ID of the tag.
* `name` The rule name identifies each rule.
* `direction`  Phase specifies the condition under which a rule applies. Pre-origin means before your server (request), post-origin is past your server (response). Valid values are `in` for request or `out` for response.
* `description` Your notes on this rule.
* `log_identifier` A comment to identify the matching rule in the access log.
* `expire_date` Expire date schedules the deaktivation of the WAF rule.
* `sort` The order in which the rules take action.
* `process_next` After a rule has been applied, the rule chain will be executed as determined.
* `enabled` Define wether this rule is enabled or not.
* `conditions` ll conditions of a rule have to be true for a rule to be executed.
* `actions` Refers to actions that are executed when all conditions of a rule are true.
