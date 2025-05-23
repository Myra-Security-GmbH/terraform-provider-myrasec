# myrasec_tags

Use this data source to look up tags.

## Example usage

```hcl
data "myrasec_tags" "www" {
    filter {
        name = "example"
    }
}
```

## Argument Reference

The following argument is supported

* `filter` (**Required**) One or more values to filter the tags.

### filter
* `name` (Optional) The tag name to filter for.

## Attributes Reference
* `tags` A list of tags.

### tags
* `id` The ID of the tag.
* `created` Date of creation.
* `modified` Date of last modification.
* `name` the name of the tag.
* `type` the type of the tag [CACHE|CONFIG|WAF|INFORMATION]
* `assignments` list of the domain/subdomain assignments

### tagAssignments
* `id` The ID of the assignment
* `created` Date of creation.
* `modified` Date of last modification.
* `type` type of the assignment (domain|subdomain)
* `title` name of the domain
* `subdomain_name` name of the subdomain