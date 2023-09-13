# myrasec_tag_cache_settings

Use this data source to look up tag cache settings.

## Example usage

```hcl
# Look for a tag cache setting
data "myrasec_tag_cache_settings" "tag_cache" {
  filter {
    tag_id = "0000"
    path   = "index"
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) One or more values to filter the tag cache settings.

### filter
* `tag_id` (Optional) The tagId from the tag cache setting.
* `path` (Optional) The path of the tag cache setting to filter for.

## Attributes Reference
* `settings` A list of tag cache settings.

### settings
* `id` The ID of the cache setting.
* `created` Date of creation.
* `modified` Date of last modification.
* `tag_id` The ID of the tag.
* `type` Type how path should match.
* `path` Path which must match to cache response.
* `ttl` Time to live.
* `not_found_ttl` How long an object will be cached. Origin responses with the HTTP codes 404 will be cached.
* `sort` The order in which the cache rules take action as long as the cache sorting is activated.
* `enabled` Define wether this cache setting is enabled or not.
* `enforce` Enforce cache TTL allows you to set the cache TTL (Cache Control: max-age) in the backend regardless of the response sent from your Origin.
