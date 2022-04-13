# myrasec_cache_setting

Provides a Myra Security redirect resource.

## Example usage

```hcl
# Create a new redirect
resource "myrasec_redirect" "redirect" {
  subdomain_name = "www.example.com"
  matching_type = "exact"
  type = "permanent"
  source = "/index_old"
  destination = "/index_new"
  depends_on = [
    myrasec_dns_record.www
  ]
}
```

## Import example
Importing an existing redirect requires the subdomain and the ID of the redirect you want to import.
```hcl
terraform import myrasec_redirect.redirect www.example.com:0000000
```

## Argument Reference

The following arguments are supported:

* `redirect_id` (Computed) ID of the redirect.
* `created` (Computed) Date of creation.
* `modified` (Computed) Date of last modification.
* `subdomain_name` (Required) The Subdomain for the redirect. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain) or the `ALL:example.com` annotation.
* `matching_type` (Required) Type to match the redirect. Valid types are: `exact`, `prefix` and `suffix`.
* `source` (Required) Location to match against.
* `destination` (Required) Target where redirect should point to.
* `comment` (Optional) A comment to describe this redirect.
* `type` (Required) Type of redirection. Valid types are: `permanent` and `redirect`.
* `enabled` (Optional) Define wether this redirect is enabled or not. Default `true`.
* `expert_mode` (Optional) Disable redirect loop detection. Default `false`.
* `sort` (Optional) The ascending order for the redirect rules. Default `0`.