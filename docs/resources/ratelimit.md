# myrasec_ratelimit

Provides a Myra Security ratelimit resource.

## Example usage

```hcl
# Create a new ratelimit
resource "myrasec_ratelimit" "ratelimit" {
  subdomain_name = "www.example.com"
  network        = "192.168.0.1/32"
  value          = 4000
}
```

## Import example
Importing an existing ratelimit requires the subdomain and the ID of the ratelimit you want to import.
```hcl
terraform import myrasec_ratelimit.ratelimit www.example.com:0000000
```

## Argument Reference

The following arguments are supported:

* `ratelimit_id` (*Computed*) ID of the ratelimit.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `subdomain_name` (**Required**) The Subdomain for the ratelimit. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain).
* `network` (**Required**) Network in CIDR notation affected by the rate limiter.
* `value` (Optional) Maximum amount of requests for the given network. Default `1000`
* `burst` (Optional) Burst defines how many requests a client can make in excess of the specified rate. Default `60`
* `timeframe` The affected timeframe in seconds for the rate limit. Default `60`