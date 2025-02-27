# myrasec_tag_information

Provides a Myra Security tag information resource.

## Example usage

```hcl
# Create a new tag information
resource "myrasec_tag_information" "example" {
    tag_id  = 0000
    key     = "example key"
    value   = "example value"
    comment = "example comment"
}
```

## Import example
Importing an existing tag information requires the tagID and the ID of the tag information you want to import.
```hcl
terraform import myrasec_tag_information.example 0000000:0000000
```

## Argument Reference

The following arguments are supported:

* `tag_id` (*Computed*) ID of the tag.
* `information_id` (*Computed*) ID of the tag information.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `key` (**Required**) An arbitrary key.
* `value` (**Required**) An arbitrary value.
* `comment` (Optional) A comment to describe this tag information. Default `""`.