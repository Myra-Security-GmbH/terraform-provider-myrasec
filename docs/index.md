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

# Create a domain
resource "myrasec_domain" "example" {
    name = "example.com"
    auto_dns = true
    auto_update = true
}

# Create a DNS record
resource "myrasec_dns_record" "www" {
    domain_name = "example.com"
    name = "www"
    record_type = "A"
    value = "192.168.0.1"
    ttl = 300
    active = true
    enabled = true
    depends_on = [ 
        myrasec_domain.example
    ]
}

# Create a new cache setting
resource "myrasec_cache_setting" "index" {
    subdomain_name = "www.example.com"
    type = "exact"
    path = "/index"
    ttl = 2678400
    not_found_ttl = 3600
    depends_on = [ 
        myrasec_dns_record.www
    ]
}

# Create a new redirect
resource "myrasec_redirect" "redirect" {
  subdomain_name = "www.example.com"
  matching_type = "exact"
  type = "permanent"
  source = "/index_old"
  destination = "/index_new"
  depends_on = [
    myrasec_dns_record.www
  ]
}
```