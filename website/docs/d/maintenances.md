# myrasec_maintenances

Use this data source to look up for maintenances.

## Example usage

```hcl
# Look up for maintenances
data "myrasec_maintenances" "example_com" {
    filter {
        subdomain_name = "example.com"
    }
}
```

## Argument Reference

The following arguments are supported

* `filter` (**Required**) One or more values to filter the maintenances

### filter
* `subdomain_name` (**Required**) The subdomain name from the maintenances.

## Attributes References
* `maintenances` A list of maintenances.

### maintenances
* `id` The ID of the maintenance.
* `created` Date of creation.
* `modified` Date of last modification.
* `active` Status of the maintenance
* `subdomain_name` The subdomain name of the maintenance
* `content` The HTML content of the maintenance
* `start` The start date of the maintenance
* `end` The end date of the maintenance