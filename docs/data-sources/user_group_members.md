# myrasec_user_group_members

Lists members of a user group with their role in that group.

## Example usage

```hcl
variable "group_id" {
  type = number
}

data "myrasec_user_group_members" "operators" {
  group_id = var.group_id
}
```

## Argument Reference

* `group_id` (**Required**) Positive ID of the group.

## Attributes Reference

* `members` List of members across all pages.
* `members.id` User ID.
* `members.role` Role in the requested group (`USER` or `ADMINISTRATOR`).
* `members.assignment_id` ID of the role assignment.
* `members.assignment_created` Date the assignment was created.
* `members.assignment_modified` Date the assignment was last modified.
* `members.login` Login name.
* `members.email` Contact email address.
* `members.firstname` First name.
* `members.lastname` Last name.
* `members.active` Whether the user account is active.
* `members.locked` Whether the user account is locked.
* `members.tfa_enabled` Whether two-factor authentication is enabled.
* `members.tfa_required` Whether two-factor authentication is required.
* `members.created` Date the user account was created.
* `members.modified` Date the user account was last modified.

## Notes

The provider requests `includeRoles=true` and selects the role for this group. Ambiguous multiple assignments or a missing role produce an error instead of guessing a role. A `myrasec_user_group_member` import ID is `<group_id>:<members.id>`, not the assignment ID. The API refuses removal of the API key's own user from a group.
