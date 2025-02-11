# myrasec_tag

Provides a Myra Security tag resource.

## Example usage

```hcl
# Create a new tag
resource "myrasec_tag" "tag_cache" {
  name = "cache tag name"
  type = "CACHE"
  assignments  {
    type           = "SUBDOMAIN"
    title          = "www.example.com"
    subdomain_name = "www.example.com"
  }
}
```

## Import example
Importing an existing tag requires the ID of the tag you want to import.
```hcl
terraform import myrasec_tag.tag_cache tag_cache:0000000
```

## Argument Reference

The following arguments are supported:

* `tag_id` (*Computed*) ID of the tag.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `type` (**Required**) Type of the tag. Valid types are: `CACHE`, `CONFIG`, `RATE_LIMIT` and `WAF`.
* `assignments` (**Required**) The domain/subDomain the tag is assigned to.
* `assignments.type` (**Required**) the type of the assignment. Valid types are: `domain`, `subdomain`.
* `assignments.title` (*Computed*) The domain name or subdomain name depending on the type.
* `assignments.subdomain_name` (**Required**) The domain name or subdomain name depending on the type.
