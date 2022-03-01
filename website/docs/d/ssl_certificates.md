# myrasec_ssl_certificates

Use this data source to look up SSL certificates.

## Example usage

```hcl
# Look for a SSL certificate
data "myrasec_ssl_certificates" "cert" {
  filter {
    domain_name = "example.com"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (Required) One or more values to filter the SSL certificates.

### filter
* `domain_name` (Required) The domain name from the SSL certificates.

## Attributes Reference
* `certificates` A list of SSL certificates.

### certificates
* `id` The ID of the SSL certificate.
* `created` Date of creation.
* `modified` Date of last modification.
