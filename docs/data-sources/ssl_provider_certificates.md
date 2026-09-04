# myrasec_ssl_provider_certificates

Use this data source to look up the certificates issued with SSL provider credentials (Sectigo or D-Trust). The certificates are returned as compact summaries without PEM data, private key and intermediates. The full certificate is available through the `myrasec_ssl_certificates` data source of the domain given by `domain_id`.

## Example usage

```hcl
data "myrasec_ssl_provider_certificates" "sectigo" {
  filter {
    credentials_id = myrasec_ssl_provider_credentials.sectigo.credentials_id
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` Filter the certificates.

### filter
* `credentials_id` (**Required**) ID of the SSL provider credentials the certificates were issued with.
* `search` (Optional) Search string.

## Attributes Reference
* `certificates` A list of certificates.

### certificates
* `id` The ID of the certificate, the same as in the `myrasec_ssl_certificates` data source.
* `created` Date of creation.
* `modified` Date of last modification.
* `subject` Subject of the certificate.
* `subject_alternatives` Names covered by the certificate.
* `algorithm` Signature algorithm of the certificate.
* `valid_from` Date and time the certificate is valid from.
* `valid_to` Date and time the certificate is valid to.
* `fingerprint` Fingerprint of the certificate.
* `serial_number` Serial number of the certificate.
* `wildcard` `true` if the certificate is a wildcard certificate.
* `extended_validation` `true` if the certificate has extended validation.
* `managed` `true` if the certificate is managed and renewed by Myra.
* `multidomain` `true` if the certificate spans more than one domain.
* `configuration_name` The SSL configuration (TLS profile) applied to the certificate.
* `request_id` The ID of the managed certificate request the certificate was issued for.
* `domain_id` The ID of the domain the certificate belongs to.
* `subdomains` Subdomains the certificate is assigned to.
