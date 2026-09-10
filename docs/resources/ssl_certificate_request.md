# myrasec_ssl_certificate_request

Provides a Myra Security managed certificate request resource (Myra Managed Certificate). A request asks Myra to obtain a certificate from Let's Encrypt, Sectigo or D-Trust, to renew it automatically and to assign it to the subdomains of the request.

The issuance is asynchronous. The request is created immediately, the certificate arrives later and the `status` attribute reports the progress. The resource does not wait for the certificate, `status` reflects the state at the last refresh.

**Requirements:** the organization needs the `Myra-Certificate` feature, which is enabled by Myra support. Sectigo and D-Trust additionally need `myrasec_ssl_provider_credentials`. Every subject alternative name must belong to a domain registered in the Myra system.

## Example usage

```hcl
# Let's Encrypt certificate for one subdomain
resource "myrasec_ssl_certificate_request" "www" {
  certificate_provider      = "LETS_ENCRYPT"
  algorithm                 = "ECDSA256"
  subject_alternative_names = ["www.example.com"]
  subdomains                = ["www.example.com"]
}

# Sectigo wildcard certificate with a custom renewal interval and TLS profile
resource "myrasec_ssl_certificate_request" "wildcard" {
  certificate_provider        = "SECTIGO"
  algorithm                   = "RSA4096"
  ssl_provider_credentials_id = myrasec_ssl_provider_credentials.sectigo.credentials_id
  renewal_interval            = 30
  signature_algorithm         = "SHA384"
  configuration_name          = "2023-mozilla-modern"

  subject_alternative_names = [
    "example.com",
    "*.example.com",
  ]

  subdomains = [
    "www.example.com",
    "api.example.com",
  ]
}
```

Domains that are not served by Myra name servers need a CNAME record for the domain validation. Use the `myrasec_ssl_certificate_request_domain_checks` data source to find out which record is expected.

## Import example
Importing an existing managed certificate request requires the ID of the request you want to import.
```hcl
terraform import myrasec_ssl_certificate_request.www 0000000
```

## Argument Reference

The following arguments are supported:

* `request_id` (*Computed*) ID of the managed certificate request.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `certificate_provider` (**Required**) The certificate provider the certificate is requested from. Valid values: `LETS_ENCRYPT`, `SECTIGO`, `DTRUST`.
* `algorithm` (**Required**) Key algorithm of the requested certificate. Valid values: `RSA2048`, `RSA4096`, `RSA8192`, `ECDSA256`, `ECDSA384`. Let's Encrypt accepts `RSA2048`, `ECDSA256` and `ECDSA384` only. The algorithm is immutable, a change replaces the request and its certificates.
* `subject_alternative_names` (**Required**) Names the certificate has to cover, for example `www.example.com` or `*.example.com`. A name covered by a wildcard in the same request is rejected at plan time, since the API drops it.
* `subdomains` (Optional) Subdomains the issued certificate is assigned to. Each subdomain has to exist as DNS record in the Myra system.
* `ssl_provider_credentials_id` (Optional) ID of the `myrasec_ssl_provider_credentials` used for the issuance. Required for `SECTIGO` and `DTRUST`, ignored for `LETS_ENCRYPT`.
* `renewal_interval` (Optional) Days before expiry at which the certificate is renewed. `0` means the system default. Accepted for `SECTIGO` and `DTRUST` only.
* `signature_algorithm` (Optional) Signature algorithm of the requested certificate. Valid values: `SHA256`, `SHA384`, `SHA512`. Empty means the system default. Accepted for `SECTIGO` and `DTRUST` only. `SHA512` cannot be combined with an ECDSA algorithm.
* `configuration_name` (Optional) SSL configuration (TLS profile) applied to the certificates issued for the request. Valid names are listed by the `myrasec_ssl_configurations` data source. The value is not part of the request object in the API, so it cannot be refreshed from the API and is empty after an import. The API has no call to reset the profile, removing the attribute keeps the stored profile and plans no change.
* `status` (*Computed*) Issuance status. `OPEN` while the certificate is being issued, `WAITING_FOR_CNAME` while the domain validation waits for a CNAME record, `CREATED` once the certificate has been issued and assigned, `FAILED` when the issuance did not succeed.
* `failure_reason` (*Computed*) Reason code when the status is `FAILED`: `CNAME_TIMEOUT`, `VALIDATION_FAILED`, `VALIDATION_ERROR`, `ORDER_FAILED` or `CERT_LOAD_FAILED`.
* `customer_actionable` (*Computed*) `true` if the failure reason is a DNS or CNAME issue the customer can resolve.
* `multi_domain` (*Computed*) `true` if the subject alternative names span more than one domain.

## Notes

* A `FAILED` request is not retried automatically. Only adding a name that no issued certificate covers or changing the `certificate_provider` re-enters the issuance. Otherwise fix the cause and replace the request.
* Adding a name that no issued certificate covers triggers a new issuance. The current certificate keeps being served until the new one arrives.
* Removing a name depends on the provider. For Let's Encrypt the issued certificate keeps covering the removed name until its next renewal, for Sectigo and D-Trust a narrowed certificate is re-issued.
* **Destroying the request removes the certificates issued for it.**
* The SSL configuration is applied with a second API call after the request has been created. If that call fails, the request is kept, the provider reports a warning and the next apply retries the configuration. The request is not replaced.
* The issued certificates are visible in the `myrasec_ssl_certificates` data source of the domain with `managed` set to `true` and, for Sectigo and D-Trust, in the `myrasec_ssl_provider_certificates` data source. They cannot be managed with the `myrasec_ssl_certificate` resource.
