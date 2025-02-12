# myrasec_tag_cache_setting

Provides a Myra Security tag cache setting resource.

## Example usage

```hcl
# Create a new cache setting
resource "myrasec_tag_cache_setting" "index" {
    tag_id        = 0000
    type          = "exact"
    path          = "/index"
    ttl           = 2678400
    not_found_ttl = 3600
    sort          = 1
}
```

## Import example
Importing an existing tag cache setting requires the tagID and the ID of the cache setting you want to import.
```hcl
terraform import myrasec_cache_setting.index 0000000:0000000
```

## Argument Reference

The following arguments are supported:

* `tag_id` (*Computed*) ID of the tag.
* `setting_id` (*Computed*) ID of the cache setting.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `type` (**Required**) Type how path should match. Valid types are: `exact`, `prefix` and `suffix`.
* `path` (**Required**) Path which must match to cache response.
* `ttl` (**Required**) Time to live.
* `not_found_ttl` (**Required**) How long an object will be cached. Origin responses with the HTTP codes 404 will be cached.
* `sort` (**Required**) The order in which the cache rules take action as long as the cache sorting is activated.
* `enabled` (Optional) Define wether this cache setting is enabled or not. Default `true`.
* `enforce` (Optional) Enforce cache TTL allows you to set the cache TTL (Cache Control: max-age) in the backend regardless of the response sent from your Origin. Default `false`.
