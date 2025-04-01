# myrasec_tag_waf_rule

Provides a Myra Security tag WAF rule resource.

## Example usage

```hcl
# Create a new tag WAF rule
resource "myrasec_tag_waf_rule" "tag_waf" {
  tag_id         = myrasec_tag.example_tag.id
  name           = "tag WAF rule name"
  description    = "Some description of this WAF rule"
  log_identifier = "IDENTIFY_ME"
  direction      = "in"
  sort           = 1
  process_next   = false
  enabled        = true
  conditions {
      matching_type = "IREGEX"
      name          = "url"
      value         = "blockme"
  }
  actions {
    type = "block"
  }
}
```

**NOTE** The `sort` parameter has to be different for every WAF rule belonging to a specific subdomain - two of the WAF rules cannot share the same sort value.

## Import example
Importing an existing tag WAF rule requires the tag ID and the ID of the WAF rule you want to import.
```hcl
terraform import myrasec_tag_waf_rule.test_tag_waf_rule 0000000:0000000
```

## Argument Reference

The following arguments are supported:
* `rule_id` (*Computed*) ID of the rule.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `rule_type` (*Computed*) The type of the rule.
* `tag_id` (**Required**) The tag ID for the rule.
* `name` (**Required**) The rule name identifies each rule.
* `direction` (**Required**) Phase specifies the condition under which a rule applies. Pre-origin means before your server (request), post-origin is past your server (response). Valid values are `in` for request or `out` for response.
* `description` (Optional) Your notes on this rule. Default `""`.
* `log_identifier` (Optional) A comment to identify the matching rule in the access log. Default `""`.
* `expire_date` (Optional) Expire date schedules the deaktivation of the WAF rule. If none is set, the rule will be active until manual deactivation.
* `sort` (Optional) The order in which the rules take action. Default `1`.
* `process_next` (Optional) After a rule has been applied, the rule chain will be executed as determined. Default `false`.
* `enabled` Define wether this rule is enabled or not. (Optional) Default `true`.
* `conditions` (Optional) All conditions of a rule have to be true for a rule to be executed. See below for argument reference.
* `actions` (**Required**) Refers to actions that are executed when all conditions of a rule are true. See below for argument reference.

### WAF rule conditions arguments
* `conditions.condition_id` (*Computed*) ID of the WAF rule condition.
* `conditions.created` (*Computed*) Date of creation.
* `conditions.modified` (*Computed*) Date of last modification.
* `conditions.name` (**Required**)
* `conditions.matching_type` (**Required**)  
    IREGEX - Pattern matching using case insensitive regex  
    REGEX - Pattern matching using case sensitive regex  
    NOT IREGEX - Pattern not matching using case insensitive regex  
    NOT REGEX - Pattern not matching using case sensitive regex  
  
    EXACT - String matching using the whole string verbatim  
    SUFFIX - String matching at the end  
    PREFIX - String matching from the beginning  
    NOT EXACT - String not matching using the whole string verbatim  
    NOT SUFFIX - String not matching at the end  
    NOT PREFIX - String not matching from the beginning  
* `conditions.value` (**Required**)
* `conditions.key` (Depends on the type)
* `conditions.alias` (*Computed*) An alias for the name of this condition
* `conditions.category` (*Computed*) The category of this condition
* `conditions.available_phases` (*Computed*) The allowed phases where this condition can be used. `1`: Request|in, `2`: Response|out, `3`: both

### WAF rule actions arguments
* `actions.type` (**Required**)
* `actions.value` (**Required**)
* `actions.custom_key` (Depends on the type)
* `actions.name` (*Computed*) The name of the action.
* `actions.available_phases` (*Computed*) The allowed phases where this action can be used. `1`: Request|in, `2`: Response|out, `3`: both


## Available WAF condtions
### Valid conditions for `direction` = `in` (request)
```hcl
name = "accept|accept_encoding|fingerprint|host|method|querystring|querystring_decode|remote_addr|url|user_agent"
matching_type = "EXACT|IREGEX|PREFIX|REGEX|SUFFIX|NOT EXACT|NOT IREGEX|NOT PREFIX|NOT REGEX|NOT SUFFIX"
value = "SOME VALUE"
```
```hcl
name = "score"
matching_type = "EQUALS|GREATER_THAN|LESS_THAN"
value = "1"
```
```hcl
name = "arg|cookie|custom_header|postarg"
matching_type = "EXACT|IREGEX|PREFIX|REGEX|SUFFIX|NOT EXACT|NOT IREGEX|NOT PREFIX|NOT REGEX|NOT SUFFIX"
key = "SOME KEY"
value = "SOME VALUE"
```
```hcl
name = "country"
matching_type = "EQUALS|NOT_EQUALS"
value = "DE,CH,AT" // ISO 3166 alpha 2 country codes | AF (Africa), AN (Antarctica), AS (Asia), EU (Europe), NA (North America), OC (Oceania) and SA (South America) for continents
```
### Valid conditions for `direction` = `out` (response)
```hcl
name = "content_type|fingerprint|remote_addr|set_cookie"
matching_type = "EXACT|IREGEX|PREFIX|REGEX|SUFFIX|NOT EXACT|NOT IREGEX|NOT PREFIX|NOT REGEX|NOT SUFFIX"
value = "SOME VALUE"
```
```hcl
name = "custom_header"
matching_type = "EXACT|IREGEX|PREFIX|REGEX|SUFFIX|NOT EXACT|NOT IREGEX|NOT PREFIX|NOT REGEX|NOT SUFFIX"
key = "SOME KEY"
value = "SOME VALUE"
```

## Available WAF actions
### Valid actions for `direction` = `in` (request)
```hcl
type = "change_upstream|remove_header|del_qs_param"
value = "SOME VALUE"
```
```hcl
type = "add_header|modify_header|remove_header_value_regex|uri_subst"
custom_key = "SOME KEY"
value = "SOME VALUE"
```
```hcl
type = "origin_rate_limit"
custom_key = "1|2|5|10|15|30|45|60|120|180|300|600|1200|3600|10800|21600|43200|64800|86400"
value = "1"
```
```hcl
type = "score"
custom_key = "+|-|*"
value = "1"
```
```hcl
type = "set_http_status"
custom_key = "301|302|404"
value = "SOME VALUE"
```
```hcl
type = "allow|block|log|verify_human"
```

### Valid actions for `direction` = `out` (response)
```hcl
type = "change_upstream|remove_header"
value = "SOME VALUE"
```
```hcl
type = "add_header|modify_header|remove_header_value_regex|uri_subst"
custom_key = "SOME KEY"
value = "SOME VALUE"
```
```hcl
type = "origin_rate_limit"
custom_key = "1|2|5|10|15|30|45|60|120|180|300|600|1200|3600|10800|21600|43200|64800|86400"
value = "1"
```
```hcl
type = "score"
custom_key = "+|-|*"
value = "1"
```
```hcl
type = "set_http_status"
custom_key = "301|302|404"
value = "SOME VALUE"
```