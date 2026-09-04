# myrasec_ssl_provider_credentials

Provides a Myra Security SSL provider credentials resource. The credentials store the account of an enterprise certificate authority (Sectigo or D-Trust) that Myra uses to request managed certificates through the `myrasec_ssl_certificate_request` resource. Let's Encrypt needs no credentials.

**Requirements:** the organization needs the `Myra-Certificate` feature, which is enabled by Myra support. Every operation requires a member of the root user group of the organization or an organization administrator.

## Example usage

```hcl
# Sectigo credentials with a server generated ACME account key pair
resource "myrasec_ssl_provider_credentials" "sectigo" {
  name                 = "Sectigo OV"
  certificate_provider = "SECTIGO"
  endpoint             = "https://acme.sectigo.com/v2/OV"
  email                = "pki@example.com"
  eab_kid              = var.sectigo_eab_kid
  eab_hmac             = var.sectigo_eab_hmac
}

# D-Trust credentials
resource "myrasec_ssl_provider_credentials" "dtrust" {
  name                 = "D-Trust"
  certificate_provider = "DTRUST"
  eab_kid              = var.dtrust_eab_kid
  eab_hmac             = var.dtrust_eab_hmac
}
```

## Import example
Importing existing SSL provider credentials requires the ID of the credentials you want to import.
```hcl
terraform import myrasec_ssl_provider_credentials.sectigo 0000000
```

The API never returns `eab_hmac` and `private_key`. After an import the next apply sends the `eab_hmac` from the configuration to the API, which rotates the stored key to that value.

## Argument Reference

The following arguments are supported:

* `credentials_id` (*Computed*) ID of the SSL provider credentials.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `name` (**Required**) User-defined label for the credentials.
* `certificate_provider` (**Required**) The certificate provider the credentials belong to. Valid values: `SECTIGO`, `DTRUST`. The EAB credentials are issued by one provider, a change replaces the credentials and detaches the certificate requests that reference them.
* `cert` (Optional) Public certificate of the ACME account key pair in PEM format. Leave `cert` and `private_key` empty to let the server generate a key pair. Supplying one without the other is rejected.
* `private_key` (Optional, Sensitive) Private key of the ACME account key pair in PEM format. Write-only: the API never returns it and discards a changed value after creation. Contact Myra support to replace the key pair.
* `email` (Optional) Contact email address of the provider account. Optional for `SECTIGO`, must be empty for `DTRUST`.
* `endpoint` (Optional) ACME directory URL of the provider product, for example `https://acme.sectigo.com/v2/OV`. Required for `SECTIGO`, since the region and the validation product are encoded in the URL. Optional for `DTRUST`, which falls back to the platform default. Removing the attribute keeps the stored endpoint.
* `eab_kid` (**Required**) External Account Binding (EAB) key identifier issued by the provider.
* `eab_hmac` (**Required**, Sensitive) External Account Binding (EAB) HMAC key issued by the provider. Write-only: the API never returns it. A changed value rotates the stored key.
* `comment` (Optional) Free-text note.

**Note:** Deleting the credentials detaches them from every `myrasec_ssl_certificate_request` that references them. The requests keep existing, their `ssl_provider_credentials_id` is cleared and their renewals need new credentials.
