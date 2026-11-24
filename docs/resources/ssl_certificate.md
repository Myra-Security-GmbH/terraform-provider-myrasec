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

## Validation: errors and warnings

The API checks the certificate, the key and the intermediate chain every time `terraform apply` sends them. `terraform plan` does not run this check, so a plan can succeed for material the apply rejects. The apply sends them:

* on create;
* on every change of `certificate` or `key`: the provider replaces the stored certificate (it sends the stored one as `cert_to_refresh` itself, you do not have to set it);
* on every other update of an existing certificate. Such an update always sends the configured `intermediate` blocks, so with intermediates configured, a change of only `subdomains` or `configuration_name` runs the chain check again and can warn or fail.

A blocking result fails the apply with one error per result, on the attribute it belongs to, with the message and the result code, for example `certificate: The certificate has expired. [LEAF_EXPIRED]`. Nothing is stored and the Terraform state stays as it was. The warnings of the same check are shown next to the errors.

A warning, for example `intermediate: ... [CHAIN_INTERMEDIATE_MISSING]` or `certificate: ... [LEAF_EXPIRES_SOON]`, does not fail the apply. It is shown as a warning diagnostic of the apply that sent the material. A refresh or a later apply without changes reads the stored certificate only and shows no warning again, so a warning never causes a new diff.

A result on one intermediate names it by its subject, for example `intermediate "CN=Example Intermediate CA,O=Example": ... [INTERMEDIATE_WRONG_KEY]`. `intermediate` is a set, so the provider does not send the blocks in the order of the configuration; the subject tells which block is meant. When the subject cannot be read, the result shows the position in the order sent (`intermediate 2`).

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
* `subdomains` (Optional) List of subdomains where to assign the certificate.
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
