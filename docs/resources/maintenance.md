# myrasec_maintenance

Provides a Myra Security maintenance resource.

## Example usage

```hcl
# Create a new maintenance
resource "myrasec_maintenance" "maintenance" {
    content        = "<html><body>Page</body></html>"
    subdomain_name = "www.example.com"
    start          = "2022-07-01T00:00:00+02:00"
    end            = "2022-07-31T23:59:59+02:00"
}
```

## Import example
Importing an existing maintenance requires the subdomain and the ID of the maintenance you want to import.
```hcl
terraform import myrasec_maintenance.maintenance www.example.com:00000000
```

## Argument Reference

The following arguments are supporeted:

* `maintenance_id` (*Computed*) ID of the maintenance.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `subdomain_name` (**Required**) The subdomain name for the maintenance.
* `start` (**Required**) The scheduled start date for the maintenance.
* `end` (**Required**) The planned end date for the maintenance.
* `content` (**Required**) The HTML content of the maintenance.
* `content_hash` (*Computed*) In the tfstate file only the hash of the content is stored.
* `active` (*Computed*) Status if the maintenance page is active or not.