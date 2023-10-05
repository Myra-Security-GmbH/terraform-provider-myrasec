# myrasec_maintenance_templates

Use this data source to look up for maintenance templates.

## Example usage

```hcl
# Look up for maintenance templates
data "myrasec_maintenance_templates" "example_com" {
    filter {
        domain_name = "example.com"
    }
}
```

## Argument Reference

The following arguments are supported

* `filter` (**Required**) One or more values to filter the maintenance templates

### filter
* `domain_name` (**Required**) The domain name from the maintenance templates.

## Attributes References
* `maintenance_templates` A list of maintenance templates.

### maintenance templates
* `id` The ID of the maintenance template.
* `created` Date of creation.
* `modified` Date of last modification.
* `name` The name of the maintenance template.
* `content` The HTML content of the maintenance template.