# myrasec_tags

Use this data source to look up tags.

## Example usage

```hcl
data "myrasec_tags" "www" {
}
```

## Attributes Reference
* `tags` A list of tags.

### tags
* `id` The ID of the tag.
* `created` Date of creation.
* `modified` Date of last modification.
* `name` the name of the tag.
* `type` the type of the tag [CACHE|SETTINGS|WAF]
* `assignments` list of the domain/subdomain assignments

### tagAssignments
* `id` The ID of the assignment
* `created` Date of creation.
* `modified` Date of last modification.
* `type` type of the assignment (domain|subdomain)
* `title` name of the domain
* `subdomain_name` name of the subdomain