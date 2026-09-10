# myrasec_ssl_certificate_request_domain_checks

Use this data source to run a live name server check for the domains of a managed certificate request. A domain that is not served by Myra name servers needs a CNAME record from `challenge_name` to `expected_cname` before the domain validation can succeed. Run the check before creating a `myrasec_ssl_certificate_request` or when a request stays in status `WAITING_FOR_CNAME`.

## Example usage

```hcl
data "myrasec_ssl_certificate_request_domain_checks" "example" {
  domains = [
    "www.example.com",
    "*.example.org",
  ]
}

# The CNAME records that have to be created at the external DNS provider of each
# domain that is not served by Myra name servers.
output "validation_cnames" {
  value = {
    for check in data.myrasec_ssl_certificate_request_domain_checks.example.checks :
    check.domain => "${check.challenge_name} CNAME ${check.expected_cname}" if !check.is_myra_ns
  }
}
```

The validation record has to exist on the name servers that are authoritative for the domain. For a domain with `is_myra_ns` set to `false` those are external name servers, so the record cannot be created with `myrasec_dns_record`. A domain served by Myra name servers needs no record.

## Argument Reference

The following arguments are supported:

* `domains` (**Required**) Domains to check, for example `www.example.com` or `*.example.org`. At most 99 domains per check.

## Attributes Reference
* `checks` A list of check results, sorted by domain. Domains whose lookup failed are absent from the list.

### checks
* `domain` The checked domain.
* `exists` `true` if the domain has name server records.
* `is_myra_ns` `true` if the domain is served by Myra name servers. No CNAME record is needed then.
* `challenge_name` The record name that has to be created as CNAME for the domain validation. Empty when no record is needed.
* `expected_cname` The target the challenge record has to point to. Empty when no record is needed.
