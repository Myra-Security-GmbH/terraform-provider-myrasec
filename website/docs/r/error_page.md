# myrasec_error_page

Provides a Myra Security error page resource.

## Example usage

```hcl
# Create a new error page
resource "myrasec_error_page" "500" {
    subdomain_name = "www.example.com"
    error_code = 500
    content = "<html><head><title>Error 500</title></head><body><h1>Error 500</h1></body></html>"
    depends_on = [ 
        myrasec_dns_record.www
    ]
}
```

## Import example
Importing an existing error page requires the subdomain and the error code or the ID of the error page you want to import.
```hcl
terraform import myrasec_error_page.500 www.example.com:500
```
or using the ID of the existing error page (0000000)
```hcl
terraform import myrasec_error_page.500 www.example.com:0000000
```
## Argument Reference

The following arguments are supported:

* `created` (computed) Date of creation.
* `modified` (computed) Date of last modification.
* `subdomain_name` (Required) The Subdomain for the error page.
* `error_code` (Required) Error code of the error page. Valid codes are: `400`, `405`, `429`, `500`, `502`, `503`, `504` and `9999` for `blocked`.
* `content` (Required) HTML content of the error page.
