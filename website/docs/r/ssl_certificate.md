# myrasec_ssl_certificate

Provides a Myra Security SSL certificate resource.

## Example usage

```hcl
# Create a new SSL certificate
resource "myrasec_ssl_certificate" "cert" {
  domain_name = "example.com"
  
  depends_on = [
    myrasec_dns_record.www
  ]
}
```

## Argument Reference

The following arguments are supported:

* `certificate_id` (Computed) ID of the SSL certificate.
* `created` (Computed) Date of creation.
* `modified` (Computed) Date of last modification.
* `domain_name` (Required) The domain for the SSL certificate.
