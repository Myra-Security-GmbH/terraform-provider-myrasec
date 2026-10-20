package myrasec

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

const settingsPrivateKey = "myra_ssl_certificate_key"
const redactedPrivateKey = "<redacted>"

func privateKeyConfigured(d *schema.ResourceData) bool {
	config := d.GetRawConfig()
	return !config.IsNull() && config.IsKnown() && !config.GetAttr(settingsPrivateKey).IsNull()
}

func redactedPrivateKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	return []string{redactedPrivateKey}
}
