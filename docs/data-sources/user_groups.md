# myrasec_user_groups

Lists the visible user group tree as a flat list, including root groups.

## Example usage

```hcl
data "myrasec_user_groups" "administered" {
  filter {
    role = "ADMINISTRATOR"
  }
}
```

## Argument Reference

* `filter` (Optional) At most one filter block. Omit it to list all visible groups.
* `filter.name` (Optional) Case-sensitive substring match on the group name. Descendants are checked even when their parent does not match.
* `filter.role` (Optional) `USER` or `ADMINISTRATOR`, case-insensitive. Passed to the API to select the group trees visible under that role.

## Attributes Reference

* `groups` Flat list of groups in tree traversal order. Pagination applies to root nodes.
* `groups.id` ID of the group.
* `groups.name` Display name.
* `groups.parent_id` Parent ID or zero for a root group.
* `groups.type` Group type (`USER`).
* `groups.members_count` Number of members.
* `groups.roles` Roles the caller holds on the group.
* `groups.created` Date of creation.
* `groups.modified` Date of last modification.
* `groups.depth` Depth in the returned tree, starting at zero for root nodes. Name filtering preserves the original depth.

## Notes

Use a returned group ID as `parent_id` for `myrasec_user_group`. Root groups can be discovered here but cannot be created, updated, deleted or imported as resources. Select the intended root explicitly when several are visible.
