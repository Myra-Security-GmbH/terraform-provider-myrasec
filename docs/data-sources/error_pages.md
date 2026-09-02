# myrasec_error_pages

Use this data source to look up error pages.

## Example usage

```hcl
# Look for a error pages
data "myrasec_error_pages" "example_com" {
  filter {
    domain_name = "example.com"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) One or more values to filter the error pages.

### filter
* `domain_name` (**Required**) The domain name from the error pages.

## Attributes Reference
* `error_pages` A list of error pages.

### error_pages
* `id` The ID of the error page.
* `created` Date of creation.
* `modified` Date of last modification.
* `subdomain_name` The Subdomain for the error page.
* `error_code` Error code of the error page. Valid codes are: `400`, `404`, `405`, `429`, `500`, `502`, `503`, `504` and `9999` for `blocked`.

Note: Content is not part of data source, it is only available in resource.