# myrasec_ratelimits

Use this data source to look up ratelimits.

## Example usage

```hcl
# Look for a ratelimit
data "myrasec_ratelimits" "ratelimits" {
  filter {
    subdomain_name = "www.example.com"
    search         = "ratelimitme"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) One or more values to filter the ratelimits.

### filter
* `subdomain_name` (**Required**) The subdomain name from the ratelimits. To point to the "General domain", you can use the `ALL-0000` (where `0000` is the ID of the domain).
* `search` (Optional) A search string to filter the ratelimits. Filers on the `network`.

## Attributes Reference
* `ratelimits` A list of ratelimits.

### ratelimits
* `id` The ID of the ratelimit.
* `created` Date of creation.
* `modified` Date of last modification.
* `subdomain_name` The Subdomain for the ratelimit.
* `network` Type to network the ratelimit.
* `value` Maximum amount of requests for the given network.
* `burst` Burst defines how many requests a client can make in excess of the specified rate.
* `timeframe` The affected timeframe in seconds for the rate limit.
* `type` Type of the rate limit setting.
