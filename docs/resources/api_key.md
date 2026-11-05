# myrasec_api_key

Provides a Myra Security API key resource.

## Example usage

```hcl
# Create a new API key
resource "myrasec_api_key" "example" {
    name = "Example"
}
```

## Import example
Importing an existing API key requires the name and the ID of the API key you want to import.
```hcl
terraform import myrasec_api_key.example example:0000000
```

## Argument Reference

The following arguments are supported:

* `key_id` (*Computed*) ID of the API key.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `name` (**Required**) Name of the API key.
* `key` (*Computed*) The API key. The attribute is sensitive: it is hidden in plans and CLI output but stored in the state.
* `secret` (*Computed*) The secret part of the API key. The API returns it only when the key is created, so it is known for keys created by this resource and empty for imported keys. The attribute is sensitive: it is hidden in plans and CLI output but stored in the state.

**Note:** The `secret` is only sent once, when creating a new API key. After this, the `secret` won't be communicated again. The provider keeps the stored value on later reads.