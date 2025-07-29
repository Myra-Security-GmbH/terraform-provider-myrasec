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
* `key` The API key.
* `secret` The secret part of the API key.
