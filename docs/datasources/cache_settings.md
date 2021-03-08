# myrasec_cache_settings

Use this data source to look up cache settings.

## Example usage

```hcl
# Look for a cache setting
data "myrasec_cache_settings" "cache" {
  filter {
    subdomain_name = "www.example.com"
    path = "index"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (Required) One or more values to filter the domains.

### filter
* `subdomain_name` (Required) The subdomain name from the cache setting.
* `path` (Optional) The path of the cache setting to filter for.

## Attributes Reference
* `settings` A list of cache settings.

### settings
* `id` The ID of the cache setting.
* `created` Date of creation.
* `modified` Date of last modification.
* `subdomain_name` The Subdomain for the cache setting.
* `type` Type how path should match.
* `path` Path which must match to cache response.
* `ttl` Time to live.
* `not_found_ttl` How long an object will be cached. Origin responses with the HTTP codes 404 will be cached.
* `sort` The order in which the cache rules take action as long as the cache sorting is activated.
* `enabled` Define wether this cache setting is enabled or not.
* `enforce` Enforce cache TTL allows you to set the cache TTL (Cache Control: max-age) in the backend regardless of the response sent from your Origin.
