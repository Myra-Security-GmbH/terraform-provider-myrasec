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
* `error_code` Error code of the error page.
* `content` HTML content of the error page.
