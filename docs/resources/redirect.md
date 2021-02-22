# myrasec_cache_setting

Provides a Myra Security redirect resource.

## Example Usage

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

## Argument Reference

The following arguments are supported:

* `subdomain_name` (Required) The Subdomain for the cache Setting.
* `redirect_id` (computed) ID of the redirect.
* `created` (computed) Date of creation.
* `modified` (computed) Date of last modification.
* `matching_type` (Required) Type to match the redirect. Valid types are: `exact`, `prefix` and `suffix`.
* `source` (Required) Location to match against.
* `destination` (Required) Target where redirect should point to.
* `type` (Required) Type of redirection. Valid types are: `permanent` and `redirect`.
* `enabled` (Optional) Define wether this redirect is enabled or not. Default `true`.
* `sort` (Optional) The ascending order for the redirect rules. Default `0`.