package myrasec

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

const settingsCertificate = "myra_ssl_certificate"
const settingsPrivateKey = "myra_ssl_certificate_key"
const redactedPrivateKey = "<redacted>"

// Preserve only a pair that is neither configured nor represented in prior state.
// Removing a managed pair must send null for both fields to restore inheritance.
func certificatePairUnmanaged(d *schema.ResourceData) bool {
	for _, name := range []string{settingsCertificate, settingsPrivateKey} {
		if !d.GetRawConfig().GetAttr(name).IsNull() {
			return false
		}
		old, _ := d.GetChange(name)
		if old.(*schema.Set).Len() > 0 {
			return false
		}
	}
	return true
}

// An entirely unconfigured pair must not become managed just because refresh saw it.
func certificatePairInState(d *schema.ResourceData) bool {
	return d.Get(settingsCertificate).(*schema.Set).Len() > 0 || d.Get(settingsPrivateKey).(*schema.Set).Len() > 0
}

// Match CustomizeDiff's set-size rule without reading any server-provided key.
func privateKeyAvailableAttributes(d *schema.ResourceData) []string {
	if d.Get(settingsPrivateKey).(*schema.Set).Len() > 0 {
		return []string{settingsPrivateKey}
	}
	return []string{}
}

func redactedPrivateKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	return []string{redactedPrivateKey}
}
