# myrasec_api_keys

Use this data source to look up API keys.

## Example usage

```hcl
# Look for an API key
data "myrasec_api_keys" "example" {
  filter {
    name           = "Example"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` Filter the API keys.

### filter
* `name` (Optional) The name of the API key.

## Attributes Reference
* `keys` A list of API keys.

### settings
* `id` The ID of the API key.
* `created` Date of creation.
* `modified` Date of last modification.
* `name` Name of the API key.
* `key` The API key. The attribute is sensitive: it is hidden in plans and CLI output but stored in the state.

**Note:** The `secret` won't be part of this datasource. The `secret` is visible only right after creating a new API key and won't be communicated again.