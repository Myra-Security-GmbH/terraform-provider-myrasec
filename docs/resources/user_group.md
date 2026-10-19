# myrasec_user_group

Manages a user subgroup. Discover an existing parent with `myrasec_user_groups`.

## Example usage

```hcl
data "myrasec_user_groups" "administered" {
  filter {
    role = "ADMINISTRATOR"
  }
}

locals {
  root_group_id = one([
    for group in data.myrasec_user_groups.administered.groups : group.id
    if group.parent_id == 0
  ])
}

resource "myrasec_user_group" "operators" {
  name      = "Operators"
  parent_id = local.root_group_id
}
```

The example expects one administered root group. If several are visible, select the intended group explicitly.

## Import example

```shell
terraform import myrasec_user_group.operators operators:42
```

The format is `<name>:<group_id>`. The name is informational and is refreshed from the API.

## Argument Reference

* `name` (**Required**) Display name of the group.
* `parent_id` (**Required**) Positive ID of a user group administered by the API key's user. Changing it moves the group in place.

## Attributes Reference

* `group_id` ID of the group.
* `type` Group type (`USER`).
* `members_count` Number of members.
* `roles` The caller's roles on the group.
* `created` Date of creation.
* `modified` Date of last modification, used for optimistic locking.

## Notes

Root groups cannot be created, updated, deleted or imported. They remain available through the data source as parents. Moving a group under its own descendant fails with an API error and preserves the previous state.

Creating a group requires ADMINISTRATOR on its parent. A 403 can mean the parent is missing, invalid, foreign or not administered by the caller.

Deletion fails while the group or any descendant still has members. Manage memberships separately with `myrasec_user_group_member` and reference this resource's `group_id` so Terraform removes those memberships first. Out-of-band memberships must be removed separately.
