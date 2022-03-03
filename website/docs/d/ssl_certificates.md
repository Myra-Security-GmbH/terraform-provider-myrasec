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
* `domain_name` The domain for the SSL certificate.
* `subject` Subject of the certificate.
* `algorithm` Signature algorithm of the certificate.
* `valid_from` Date and time the certificate is valid from.
* `valid_to` Date and time the certificate is valid to.
* `fingerprint` RSA 256 fingerprint of the certificate.
* `serial_number` Serial number of the certificate.
* `subject_alternatives` Sub domain(s) the certificate is valid for.
* `wildcard` True if the certificate contains a wildcard domain.
* `extended_validation` True if the certificate has extended validation.
* `subdomains` List of subdomains where to assign the certificate.
* `intermediates` A list of intermediate certificate(s).
* `intermediates.subject` Subject of the intermediate certificate.
* `intermediates.algorithm` Signature algorithm of the intermediate certificate.
* `intermediates.valid_from` Date and time the intermediate certificate is valid from.
* `intermediates.valid_to` Date and time the intermediate certificate is valid to.
* `intermediates.fingerprint` RSA 256 fingerprint of the intermediate certificate.
* `intermediates.serial_number` Serial number of the intermediate certificate.
* `intermediates.issuer` Issuer of the intermediate certificate.
