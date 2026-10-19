# myrasec_user_permission

Manages one direct object permission granted to a user.

## Example usage

```hcl
variable "user_id" {
  type = number
}

resource "myrasec_user_permission" "read_domains" {
  user_id = var.user_id
  action      = "READ"
  object_type = "Domain"
}
```

## Import example

```shell
terraform import myrasec_user_permission.read_domains 42:91
```

The format is `<user_id>:<permission_id>`. Discover IDs with `myrasec_user_permissions`.

## Argument Reference

Every input requires replacement when changed because the API has no permission update endpoint.

* `user_id` (**Required**, ForceNew) Positive ID of the receiving user.
* `action` (**Required**, ForceNew) One of `READ`, `CREATE`, `EDIT`, `SWITCH`, `ADMIN`, `AGENT_MODE`, `USER_MODE`, `CACHE_CLEAR`, `REVIEW`, `PUBLISH`, `LOADBALANCE_READ` or `LOADBALANCE_EDIT`.
* `object_type` (**Required**, ForceNew) API object type, such as `Domain` or `DnsRecord`. The API validates the available types and actions.
* `object_instance` (Optional, ForceNew) Positive ID of a specific object. Omitted or zero means all instances of the type within the visible scope.
* `scopes` (Optional, ForceNew) Set of positive permission IDs explicitly requested to restrict this grant. The API may append required parent scopes. These additions do not change the configured set. Removing a requested scope outside Terraform plans replacement to restore the restriction.

## Attributes Reference

* `permission_id` ID of the permission row.
* `effective_scopes` Complete set of scope IDs returned by the API, including requested restrictions and derived parent scopes.
* `name` Display name derived from the target object. It cannot be configured.
* `value` Auxiliary value derived from the target object. It cannot be configured.
* `created` Date of creation.
* `modified` Date of last modification.
* `parents` Parent permissions reported by the API, each with `id`, `action`, `object_type` and `object_instance`.

## Notes

Granting `EDIT`, `REVIEW` or `PUBLISH` also grants `READ`. `LOADBALANCE_EDIT` also grants `LOADBALANCE_READ`. These implied rows are not adopted into this resource. Deleting an EDIT grant does not remove its implied READ grant. Import implied permissions separately if they must also be managed by Terraform.

Revoking READ cascades to EDIT and CREATE permissions on the same type and instance and down the object-type tree. A later refresh detects rows removed by this cascade. Destroying an already removed row succeeds. Avoid overlapping grants with conflicting lifecycles. When a separately managed READ must outlive an EDIT grant, declare the READ dependency explicitly and create or import it first.

The API deduplicates grants by recipient, object type, object instance and action, ignoring scopes. The provider rejects an existing direct grant with its import ID. Do not use `create_before_destroy` when changing only scopes: the replacement would duplicate the existing row. Concurrent creates in this provider process are serialized. Separate Terraform processes and external writers must coordinate ownership to avoid races.

Import adopts the existing scope chain as API-managed: leave `scopes` omitted for a clean plan and inspect `effective_scopes`. Adding explicit `scopes` after import plans replacement.

All reads request scoped permissions as well. Root group permissions are supported even though root groups themselves cannot be managed with `myrasec_user_group`.

The user's permission list can also contain inherited group permissions. This resource only manages rows whose recipient type is `USER`. Import inherited rows through `myrasec_user_group_permission` on their owning group instead.
