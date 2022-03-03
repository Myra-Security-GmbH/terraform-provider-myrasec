# myrasec_ssl_certificate

Provides a Myra Security SSL certificate resource.

## Example usage

```hcl
# Create a new SSL certificate
resource "myrasec_ssl_certificate" "cert" {
  domain_name = "example.com"
  subdomains = [
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
* `subject` (Computed) Subject of the certificate.
* `algorithm` (Computed) Signature algorithm of the certificate.
* `valid_from` (Computed) Date and time the certificate is valid from.
* `valid_to` (Computed) Date and time the certificate is valid to.
* `fingerprint` (Computed) RSA 256 fingerprint of the certificate.
* `serial_number` (Computed) Serial number of the certificate.
* `subject_alternatives` (Computed) Sub domain(s) the certificate is valid for.
* `wildcard` (Computed) True if the certificate contains a wildcard domain.
* `extended_validation` (Computed) True if the certificate has extended validation.
* `subdomains` (Optional) List of subdomains where to assign the certificate.
* `cert_to_refresh` (Optional) List of subdomains where to assign the certificate. Default `0`.
* `cert_refresh_forced` (Optional) List of subdomains where to assign the certificate. Default `true`.
* `intermediate` (Optional) A list of intermediate certificate(s).
* `intermediate.subject` (Computed) Subject of the intermediate certificate.
* `intermediate.algorithm` (Computed) Signature algorithm of the intermediate certificate.
* `intermediate.valid_from` (Computed) Date and time the intermediate certificate is valid from.
* `intermediate.valid_to` (Computed) Date and time the intermediate certificate is valid to.
* `intermediate.fingerprint` (Computed) RSA 256 fingerprint of the intermediate certificate.
* `intermediate.serial_number` (Computed) Serial number of the intermediate certificate.
* `intermediate.issuer` (Computed) Issuer of the intermediate certificate.
