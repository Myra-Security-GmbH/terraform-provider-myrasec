# myrasec_user_permissions

Lists object permissions visible for a user, including scoped rows. Use the result for audits and import discovery.

## Example usage

```hcl
variable "user_id" {
  type = number
}

data "myrasec_user_permissions" "domains" {
  user_id = var.user_id
  filter {
    object_type = "Domain"
  }
}
```

## Argument Reference

* `user_id` (**Required**) Positive ID of the user.
* `filter` (Optional) At most one filter block.
* `filter.object_type` (Optional) Exact object type to include. Omit the filter to return every type.

## Attributes Reference

* `permissions` List of permission rows.
* `permissions.permission_id` ID used in the second part of an import ID.
* `permissions.object_permission_type` Recipient kind (`USER` or `GROUP`).
* `permissions.action` Granted action.
* `permissions.object_type` Target object type.
* `permissions.object_instance` Target object ID or zero for all instances within scope.
* `permissions.name` Display name derived from the target object.
* `permissions.value` Auxiliary value derived from the target object.
* `permissions.scopes` Set of permission IDs restricting the grant.
* `permissions.parents` Parent permissions, each with `id`, `action`, `object_type` and `object_instance`.
* `permissions.created` Date of creation.
* `permissions.modified` Date of last modification.

## Notes

The data source always requests `all=true`, so scoped permissions and root group grants remain visible. Implied READ permissions are included. See [myrasec_user_permission](../resources/user_permission.md) for duplicate handling and revoke cascades.

User results include inherited group permissions. Only rows with `object_permission_type = "USER"` can be imported as `myrasec_user_permission`. The data source does not expose the owning group ID for inherited rows; discover that group through its own permissions data source before importing.
