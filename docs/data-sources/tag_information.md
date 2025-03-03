# myrasec_tag_information

Use this data source to look up tag information.

## Example usage

```hcl
# Look for a tag information
data "myrasec_tag_information" "tag_information" {
  filter {
    tag_id = "0000"
    key    = "example-key"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) One or more values to filter the tag information.

### filter
* `tag_id` (Optional) The tagId from the tag information.
* `key` (Optional) The key of the tag information to filter for.

## Attributes Reference
* `information` A list of tag information.

### information
* `id` The ID of the tag information.
* `created` Date of creation.
* `modified` Date of last modification.
* `tag_id` The ID of the tag.
* `key` Key of the information.
* `value` Value of the information.
* `comment` A comment to describe this tag information.
