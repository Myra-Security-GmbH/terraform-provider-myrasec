# myrasec_ssl_certificate

Provides a Myra Security SSL certificate resource.

**Myra managed certificates can not be handled with this resource type**

## Example usage

```hcl
# Create a new SSL certificate
resource "myrasec_ssl_certificate" "cert" {
  domain_name = "example.com"
  subdomains  = [
    "www.example.com"
  ]
  cert_refresh_forced = true
  cert_to_refresh = 0

  certificate = <<EOT
-----BEGIN CERTIFICATE-----
MIIFGDCC...................
...........................
...........................
..............XJrj3q
-----END CERTIFICATE-----
EOT

  key = <<EOF
-----BEGIN PRIVATE KEY-----  
MIIEvwIB...................
...........................
...........................
......ZbLiewuw==
-----END PRIVATE KEY-----
EOF

  intermediate {
    certificate = <<-EOF
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gA..............
...........................
...........................
.............Hwg==
-----END CERTIFICATE-----
EOF
  }

    intermediate {
      certificate = <<-EOF
-----BEGIN CERTIFICATE-----
MIIFYDCCBE.................
...........................
...........................
..........dy753ec5
-----END CERTIFICATE-----
EOF
  }
}
```

## Import example
Importing an existing SSL certificate requires the domain name and the ID of the certificate you want to import.
```hcl
terraform import myrasec_ssl_certificate.cert example.com:0000000
```

## Argument Reference

The following arguments are supported:

* `certificate_id` (*Computed*) ID of the SSL certificate.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `configuration_name` (Optional) Specific ssl configuration for ciphers and protocols.
* `domain_name` (**Required**) The domain for the SSL certificate.
* `subject` (*Computed*) Subject of the certificate.
* `algorithm` (*Computed*) Signature algorithm of the certificate.
* `valid_from` (*Computed*) Date and time the certificate is valid from.
* `valid_to` (*Computed*) Date and time the certificate is valid to.
* `fingerprint` (*Computed*) RSA 256 fingerprint of the certificate.
* `serial_number` (*Computed*) Serial number of the certificate.
* `subject_alternatives` (*Computed*) Sub domain(s) the certificate is valid for.
* `wildcard` (*Computed*) True if the certificate contains a wildcard domain.
* `extended_validation` (*Computed*) True if the certificate has extended validation.
* `subdomains` (Optional) List of subdomains where to assign the certificate. Some changes of other resources also change the subdomains of the certificate on the server and with them its `modified` timestamp: deleting the last DNS record of a name or renaming it removes the name from the certificate, and creating a DNS record can assign it to a certificate that covers it when automatic certificate requests are enabled for the organization. When the same apply changes `subdomains` of this certificate in the same way, the API refuses the certificate update as "edited in the meantime". The provider then re-reads the certificate and sends the update once more, but only if every subdomain the server removed or added is removed or added by this apply as well and the certificate and its TLS configuration are unchanged. Any other change made on the server in the meantime is reported as an error and never overwritten.
* `cert_to_refresh` (Optional) ID of the certificate to refresh. Default `0`.
* `cert_refresh_forced` (Optional) `true` to force certificate update. Default `true`.
* `intermediate` (Optional) A list of intermediate certificate(s).
* `intermediate.subject` (*Computed*) Subject of the intermediate certificate.
* `intermediate.algorithm` (*Computed*) Signature algorithm of the intermediate certificate.
* `intermediate.valid_from` (*Computed*) Date and time the intermediate certificate is valid from.
* `intermediate.valid_to` (*Computed*) Date and time the intermediate certificate is valid to.
* `intermediate.fingerprint` (*Computed*) RSA 256 fingerprint of the intermediate certificate.
* `intermediate.serial_number` (*Computed*) Serial number of the intermediate certificate.
* `intermediate.issuer` (*Computed*) Issuer of the intermediate certificate.
