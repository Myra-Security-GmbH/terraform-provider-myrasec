# myrasec_cache_setting

Provides a Myra Security cache setting resource.

## Example usage

```hcl
# Create a new cache setting
resource "myrasec_cache_setting" "index" {
    subdomain_name = "www.example.com"
    type = "exact"
    path = "/index"
    ttl = 2678400
    not_found_ttl = 3600
    depends_on = [ 
        myrasec_dns_record.www
    ]
}
```

## Argument Reference

The following arguments are supported:

* `setting_id` (computed) ID of the cache setting.
* `created` (computed) Date of creation.
* `modified` (computed) Date of last modification.
* `subdomain_name` (Required) The Subdomain for the cache setting.
* `type` (Required) Type how path should match. Valid types are: `exact`, `prefix` and `suffix`.
* `path` (Required) Path which must match to cache response.
* `ttl` (Required) Time to live.
* `not_found_ttl` (Required) How long an object will be cached. Origin responses with the HTTP codes 404 will be cached.
* `sort` (Optional) The order in which the cache rules take action as long as the cache sorting is activated. Default `0`.
* `enabled` (Optional) Define wether this cache setting is enabled or not. Default `true`.
* `enforce` (Optional) Enforce cache TTL allows you to set the cache TTL (Cache Control: max-age) in the backend regardless of the response sent from your Origin. Default `false`.
