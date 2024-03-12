# myrasec_domain

Provides a Myra Security domain resource.

## Example usage

```hcl
# Create a domain
resource "myrasec_domain" "example-domain" {
    name        = "example.com"
    auto_update = true
}
```

## Import example
Importing an existing domain requires the domain name or the domain ID of the domain you want to import.
```hcl
terraform import myrasec_domain.example example.com
```
or  
```hcl
terraform import myrasec_domain.example 0000000
```
## Argument Reference

The following arguments are supported:

* `domain_id` (*Computed*) ID of the domain.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `name` (**Required**) Domain name.
* `auto_update` (Optional) Auto update flag for the domain. Default `true`.
