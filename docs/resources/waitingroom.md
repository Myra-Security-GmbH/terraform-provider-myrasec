# myrasec_waitingroom

Provides a Myra Security waitingroom resource.

## Example usage

```hcl
# Create a new waitingroom
resource "myrasec_waitingroom" "waitingroom" {
   name = "test"
   subdomain_name = "www.example.com"
   max_concurrent = 100
   session_timeout = 60
   wait_refresh = 30
   paths = ["test_path_1", "test_path_2"]
   content = "<html>Content</html>"
}
```

## Import example
Importing an existing waitingroom requires the subdomain and the ID of the waitingroom you want to import.
```hcl
terraform import myrasec_waitingroom.waitingroom www.example.com:0000000
```

## Argument Reference

The following arguments are supported:

* `waitingroom_id` (*Computed*) ID of the Waiting Room.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `vhost_id` (*Computed*) The VHost ID for the Waiting Room.
* `subdomain_name` (**Required**) Identifies the subdomain via a FQDN (Full Qualified Domain Name) that the Waiting Room belongs to. This value is optional and is determined from the VHost based on its ID.
* `name` (**Required**) Name of the Waiting Room.
* `max_concurrent` (**Required**) The maximum number of visitors allowed on the Origin server at the same time. As soon as this value is exceeded, each additional visitor is directed to the waiting room.
* `session_timeout` (**Required**) Defines the duration in seconds during which an inactive session may access the Origin server. If the same session does not access the server again during this time, access for that session will be disabled.
* `wait_refresh` (**Required**) Defines the duration in seconds after which the waiting page is reloaded. If the session is not accessed again after the third reload, the session will be removed from the queue.
* `paths` (**Required**) Defines a specific path within the apex domain or subdomain for which the waiting room is to be valid. The path needs to be defined as a regular expression. The default value in the PATH field is ".". If the default value "." is used as the path, the waiting pages and settings of all waiting rooms with a specific path of the corresponding apex domain or subdomain are overwritten.
* `content` (**Required**) The HTML content of the Waiting Room.
* `content_hash` (*Computed*) In the tfstate file only the hash of the content is stored.