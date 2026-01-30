# Myra Security provider

The myrasec provider is used to interact with the Myra Security API

## Basic Configuration

In order to use the Myra Security Provider you first need your API_KEY and your API_SECRET.

## Example Usage
```hcl
terraform {
  required_providers {
    myrasec = {
      source  = "Myra-Security-GmbH/myrasec"
      version = "~> 1.0.0"
    }
  }
}

# Configure the Myra Security Provider
provider "myrasec" {
  api_key = "${var.myra_api_key}"
  secret = "${var.myra_api_secret}"
}
...
```

In case you prefer to use the API token for authentication, you can use this token, too:
```
# Configure the Myra Security Provider
provider "myrasec" {
  api_token = "${var.myra_api_token}"
}
```

## Variables
Some attributes in the resources require specific values, therefore we created a list of variables that you can import to your terraform project:
[Variable list](variables.md)