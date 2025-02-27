# myrasec_waitingrooms

Use this data source to look up waitingrooms. It is possible to fetch waitingrooms for single subdomain or for entire domain.

## Example usage for subdomain

```hcl
# Look for a waitingroom
data "myrasec_waitingrooms" "waitingrooms" {
  filter {
    subdomain_name = "www.example.com"
  }
}
```
## Example usage for domain

```hcl
# Look for a waitingroom
data "myrasec_waitingrooms" "waitingrooms" {
  filter {
    domain_id = 123
  }
}
```

## Argument Reference

The following arguments are supported:

* `filter` (**Required**) Exactly one value is required to filter the waitingrooms.

### filter
* `subdomain_name` (**Optional**) The subdomain name for the waitingrooms.
* `domain_id` (**Optional**) The domain ID for the waitingrooms.

## Attributes Reference
* `waitingrooms` A list of waitingrooms.

### waitingrooms
* `waitingroom_id` The ID of the waitingroom.
* `created` Date of creation.
* `modified` Date of last modification.
* `vhost_id` The ID of the Vhost.
* `subdomain_name` Identifies the subdomain via a FQDN (Full Qualified Domain Name) that the Waiting Room belongs to. This value is optional and is determined from the VHost based on its ID.
* `name` Name of the waitingroom.
* `paths` Defines a specific path within the apex domain or subdomain for which the waiting room is to be valid. The path needs to be defined as a regular expression. The default value in the PATH field is ".". If the default value "." is used as the path, the waiting pages and settings of all waiting rooms with a specific path of the corresponding apex domain or subdomain are overwritten.
* `max_concurrent` The maximum number of visitors allowed on the Origin server at the same time. As soon as this value is exceeded, each additional visitor is directed to the waiting room.
* `session_timeout` Defines the duration in seconds during which an inactive session may access the Origin server. If the same session does not access the server again during this time, access for that session will be disabled.
* `wait_refresh` Defines the duration in seconds after which the waiting page is reloaded. If the session is not accessed again after the third reload, the session will be removed from the queue.
* `content` The HTML content of the Waiting Room.

Note: Content is not part of data source, it is only available in resource.