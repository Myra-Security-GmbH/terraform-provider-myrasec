# myrasec_domain

Provides a Myra Security domain resource.

## Example Usage

```hcl
# Create a domain
resource "myrasec_domain" "example" {
    name = "example.com"
    auto_dns = true
    auto_update = true
}
```

## Argument Reference

The following arguments are supported:

* `domain_id` (computed) ID of the domain.
* `created` (computed) Date of creation.
* `modified` (computed) Date of last modification.
* `name` (Required) Domain name.
* `auto_update` (Optional) Auto update flag for the domain. Default `true`.
* `auto_dns` (Optional) Auto DNS flag for the domain. Default `true`.
* `paused` (Optional) Shows if Myra is paused for this domain. Default `false`.
* `paused_until` (Optional) Date until Myra will be automatically reactivated.