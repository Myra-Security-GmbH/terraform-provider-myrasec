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
* `name` The name of the tag.
* `type` The type of the tag [CACHE|CONFIG|WAF|INFORMATION]
* `assignments` List of the domain/subdomain assignments
* `sort` Order in which `WAF` tags are processed
* `global` Identifies global tags.

### tagAssignments
* `id` The ID of the assignment
* `created` Date of creation.
* `modified` Date of last modification.
* `type` Type of the assignment (domain|subdomain)
* `title` Name of the domain
* `subdomain_name` Name of the subdomain