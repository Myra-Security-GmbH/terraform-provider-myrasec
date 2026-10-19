# myrasec_users

Lists users visible to the API key. Use this data source to resolve IDs for memberships and direct permissions.

## Example usage

```hcl
data "myrasec_users" "operator" {
  filter {
    search = "operator@example.com"
  }
}

locals {
  operator_id = one([
    for user in data.myrasec_users.operator.users : user.id
    if user.login == "operator@example.com"
  ])
}
```

## Argument Reference

* `filter` (Optional) At most one filter block. Omit it to list all visible users.
* `filter.search` (Optional) Search text passed to the API. Search can return several users; match the exact login when resolving a single ID.

## Attributes Reference

* `users` List of users across all pages.
* `users.id` User ID.
* `users.login` Login name.
* `users.email` Contact email address.
* `users.firstname` First name.
* `users.lastname` Last name.
* `users.active` Whether the account is active.
* `users.locked` Whether the account is locked.
* `users.tfa_enabled` Whether two-factor authentication is enabled.
* `users.tfa_required` Whether two-factor authentication is required.
* `users.created` Date of creation.
* `users.modified` Date of last modification.

## Notes

Only a caller with ADMINISTRATOR in at least one group can list the organization. Other callers see only themselves. The provider does not create or manage user accounts.
