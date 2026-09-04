# myrasec_ssl_certificate_requests

Use this data source to look up managed certificate requests (Myra Managed Certificates).

## Example usage

```hcl
# Look for all failed requests of a domain
data "myrasec_ssl_certificate_requests" "failed" {
  filter {
    domain_name = "example.com"
    status      = ["FAILED"]
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` Filter the managed certificate requests.

### filter
* `domain_name` (Optional) Restrict the result to requests of one domain.
* `status` (Optional) Statuses to include: `OPEN`, `WAITING_FOR_CNAME`, `CREATED`, `FAILED`. Defaults to all statuses.
* `search` (Optional) Restrict the result to requests with an assigned subdomain whose name contains the search string. Requests without assigned subdomains are omitted when `search` is set.

## Attributes Reference
* `requests` A list of managed certificate requests.

### requests
* `id` The ID of the request.
* `created` Date of creation.
* `modified` Date of last modification.
* `certificate_provider` The certificate provider: `LETS_ENCRYPT`, `SECTIGO` or `DTRUST`.
* `algorithm` Key algorithm of the requested certificate.
* `status` Issuance status: `OPEN`, `WAITING_FOR_CNAME`, `CREATED` or `FAILED`.
* `failure_reason` Reason code when the status is `FAILED`.
* `customer_actionable` `true` if the failure reason is a DNS or CNAME issue the customer can resolve.
* `multi_domain` `true` if the subject alternative names span more than one domain.
* `subject_alternative_names` Names the certificate has to cover.
* `subdomains` Subdomains the issued certificate is assigned to.
* `ssl_provider_credentials_id` ID of the SSL provider credentials used for the issuance.
* `renewal_interval` Days before expiry at which the certificate is renewed.
* `signature_algorithm` Signature algorithm of the requested certificate.
