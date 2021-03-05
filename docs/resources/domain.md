# myrasec_domain

Provides a Myra Security domain resource.

## Example Usage

```hcl
# Create a domain
resource "myrasec_domain" "example" {
    name = "example.com"
    auto_update = true
}
```

## Argument Reference

The following arguments are supported:

* `domain_id` (Computed) ID of the domain.
* `created` (Computed) Date of creation.
* `modified` (Computed) Date of last modification.
* `name` (Required) Domain name.
* `auto_update` (Optional) Auto update flag for the domain. Default `true`.
* `paused` (Optional) Shows if Myra is paused for this domain. Default `false`.
* `paused_until` (Optional) Date until Myra will be automatically reactivated.