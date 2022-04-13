# myrasec_ratelimit

Provides a Myra Security rate limit resource.

## Example usage

```hcl
# Create a new rate limit setting
resource "myrasec_ratelimit" "ratelimit" {
  subdomain_name = "www.example.com"
  network = "192.168.0.0/24"
  burst = 50
  timeframe = 60
  value = 1000
  depends_on = [
    myrasec_dns_record.www
  ]
}
```

## Import example
Importing an existing rate limit requires the subdomain and the ID of the rate limit setting you want to import.
```hcl
terraform import myrasec_ratelimit.ratelimit www.example.com:0000000
```

## Argument Reference

The following arguments are supported:

* `ratelimit_id` (Computed) ID of the rate limit setting.
* `created` (Computed) Date of creation.
* `modified` (Computed) Date of last modification.
* `type` (Computed) Type of the rate limit setting.
* `subdomain_name` (Required) The Subdomain for the rate limit setting. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain) or the `ALL:example.com` annotation.
* `network` (Required) Network in CIDR notation affected by the rate limiter.
* `value` (Optional) Maximum amount of requests for the given network. Valid values are `4000`, `2000`, `1000`, `500`, `100`, `60` or `0`. Default `1000`
* `burst` (Optional) Burst defines how many requests a client can make in excess of the specified rate. Default `50`
* `timeframe` (Optional) The affected timeframe in seconds for the rate limit. Valid timeframe values are `1`, `2`, `5`, `10`, `15`, `30`, `45`, `60`, `120`, `180`, `300`, `600`, `1200` or `3600`. Default `60`.
