# myrasec_user_group_member

Manages one user's membership and role in a user group.

## Example usage

```hcl
variable "group_id" {
  type = number
}

data "myrasec_users" "operator" {
  filter {
    search = "operator@example.com"
  }
}

resource "myrasec_user_group_member" "operator" {
  group_id = var.group_id
  user_id  = one([
    for user in data.myrasec_users.operator.users : user.id
    if user.login == "operator@example.com"
  ])
  role = "USER"
}
```

## Import example

```shell
terraform import myrasec_user_group_member.operator 42:73
```

The format is `<group_id>:<user_id>`.

## Argument Reference

* `group_id` (**Required**, ForceNew) Positive ID of the group.
* `user_id` (**Required**, ForceNew) Positive ID of the user. Resolve it through `myrasec_users`.
* `role` (**Required**) `USER` or `ADMINISTRATOR`, case-insensitive and normalized to uppercase. A change updates the membership in place.

## Attributes Reference

* `assignment_id` ID of the role assignment.
* `created` Date the assignment was created.
* `modified` Date the assignment was last modified.

## Notes

The provider rejects creation for an existing member and returns an import ID. Import existing memberships when adopting them. Role changes use the API's upsert operation in place. Manage each group/user pair in only one resource. Writes are serialized within this provider process; separate Terraform processes and external writers must coordinate ownership.

Deleting the resource removes every role assignment for that user in the group. The API refuses self-removal with a 403, so do not manage the API key's own membership if it must later be destroyed. A user from another organization cannot be added.
