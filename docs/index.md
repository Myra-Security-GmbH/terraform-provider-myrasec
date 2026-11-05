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

## Argument Reference

The following arguments are supported in the `provider` block. Most of them can also be set through the environment variable named next to it.

* `api_key` (Optional) The API key. Environment variable `MYRASEC_API_KEY`.
* `secret` (Optional) The secret part of the API key. Environment variable `MYRASEC_API_SECRET`.
* `api_token` (Optional) An API token, used instead of `api_key` and `secret`. Environment variable `MYRASEC_API_TOKEN`.
* `language` (Optional) The API language. Default `en`.
* `api_base_url` (Optional) API base URL with the `%s` placeholder for the API method. It must use `https`. A plain `http` URL is refused unless it points to the local machine or `allow_insecure_http` is set. Default `https://apiv2.myracloud.com/%s`. Environment variable `MYRASEC_API_BASE_URL`.
* `api_cache_ttl` (Optional) Lifetime of cached API responses in seconds. Default `30`. Environment variable `MYRASEC_API_CACHE_TTL`.
* `allow_insecure_http` (Optional) Allow a plain `http` API base URL on a host other than the local machine. The API credentials are sent in clear text then, use it for a test endpoint only. Default `false`. Environment variable `MYRASEC_ALLOW_INSECURE_HTTP`.

## Transport

The provider refuses redirects from `https` to `http` and redirects to another host. Requests that fail with HTTP status 429 are retried, with the delay from the `Retry-After` header when the API sends one. Read requests are also retried on 500, 502, 503 and 504. Write requests are retried on 503 only when the response carries `Retry-After`, and never on 500, 502 and 504, as the API may have applied them already.

Lists are read in pages of 250 entries. An import whose final read fails reports the error instead of a resource with an empty ID.

## Variables
Some attributes in the resources require specific values, therefore we created a list of variables that you can import to your terraform project:
[Variable list](variables.md)