# myrasec_redirects

Use this data source to look up redirects.

## Example usage

```hcl
# Look for a redirect
data "myrasec_redirects" "redirect" {
  filter {
    subdomain_name = "www.example.com"
    search = "redirectme"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (Required) One or more values to filter the redirects.

### filter
* `subdomain_name` (Required) The subdomain name from the redirects. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain) or the `ALL:example.com` annotation.
* `search` (Optional) A search string to filter the redirects. Filers on the `source` and the `destination` fields.

## Attributes Reference
* `redirects` A list of redirects.

### redirects
* `id` The ID of the redirect.
* `created` Date of creation.
* `modified` Date of last modification.
* `subdomain_name` The Subdomain for the redirect.
* `matching_type` Type to match the redirect.
* `source` Location to match against.
* `destination` Target where redirect should point to.
* `comment` Comment to describe this redirect.
* `type` Type of redirection.
* `enabled` Define wether this redirect is enabled or not.
* `sort` The ascending order for the redirect rules.