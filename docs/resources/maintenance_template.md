# myrasec_maintenance_template

Provides a Myra Security maintenance templaste resource.

## Example usage

```hcl
# Create a new maintenance template
resource "myrasec_maintenance_template" "template" {
    domain_name = "www.example.com"
    name        = "Example template"
    content     = "<html><body>Page</body></html>"
}
```

## Import example
Importing an existing maintenance template requires the domain name and the ID of the maintenance template you want to import.
```hcl
terraform import myrasec_maintenance_template.template example.com:00000000
```

## Argument Reference

The following arguments are supporeted:

* `maintenance_template_id` (*Computed*) ID of the maintenance template.
* `created` (*Computed*) Date of creation.
* `modified` (*Computed*) Date of last modification.
* `domain_name` (**Required**) The domain name for the maintenance template.
* `name` (**Required**) The name of the maintenance template.
* `content` (**Required**) The HTML content of the maintenance template.
* `content_hash` (*Computed*) In the tfstate file only the hash of the content is stored.
