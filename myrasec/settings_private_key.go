package myrasec

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const settingsCertificate = "myra_ssl_certificate"
const settingsPrivateKey = "myra_ssl_certificate_key"
const redactedPrivateKey = "<redacted>"

// Preserve only a pair that is neither configured nor represented in prior state.
// Removing a managed pair must send null for both fields to restore inheritance.
func certificatePairUnmanaged(d *schema.ResourceData, clean bool) bool {
	// Destroy has no raw configuration; only the existing state establishes ownership.
	if clean {
		return !certificatePairInState(d)
	}
	oldAttributes, _ := d.GetChange("available_attributes")
	for _, name := range []string{settingsCertificate, settingsPrivateKey} {
		if !d.GetRawConfig().GetAttr(name).IsNull() {
			return false
		}
		old, _ := d.GetChange(name)
		if old.(*schema.Set).Len() > 0 || oldAttributes.(*schema.Set).Contains(name) {
			return false
		}
	}
	return true
}

// An entirely unconfigured pair must not become managed just because refresh saw it.
func certificatePairInState(d *schema.ResourceData) bool {
	return d.Get(settingsCertificate).(*schema.Set).Len() > 0 || d.Get(settingsPrivateKey).(*schema.Set).Len() > 0 ||
		d.Get("available_attributes").(*schema.Set).Contains(settingsCertificate) ||
		d.Get("available_attributes").(*schema.Set).Contains(settingsPrivateKey)
}

// Retain key ownership, including an explicit empty override, without reading server keys.
func privateKeyAvailableAttributes(d *schema.ResourceData) []string {
	if d.Get(settingsPrivateKey).(*schema.Set).Len() > 0 || d.Get("available_attributes").(*schema.Set).Contains(settingsPrivateKey) {
		return []string{settingsPrivateKey}
	}
	return []string{}
}

// Version 0 refreshes listed every list setting in available_attributes, including the []
// the API returns for an unset certificate, so those entries never meant ownership.
// The schema type did not change with version 1, so the current type also describes version 0.
func certificatePairStateUpgraders(r *schema.Resource) []schema.StateUpgrader {
	return []schema.StateUpgrader{{
		Version: 0,
		Type:    r.CoreConfigSchema().ImpliedType(),
		Upgrade: upgradeCertificatePairState,
	}}
}

// Drop pair members with an empty set from available_attributes. A configured [] override
// is planned back by CustomizeDiff, at the cost of one update. Destroy runs no CustomizeDiff,
// so destroying before the first plan after the upgrade leaves such an override in place.
func upgradeCertificatePairState(_ context.Context, rawState map[string]any, _ any) (map[string]any, error) {
	attributes, ok := rawState["available_attributes"].([]any)
	if !ok {
		return rawState, nil
	}
	kept := make([]any, 0, len(attributes))
	for _, name := range attributes {
		if name == settingsCertificate || name == settingsPrivateKey {
			if values, _ := rawState[name.(string)].([]any); len(values) == 0 {
				continue
			}
		}
		kept = append(kept, name)
	}
	rawState["available_attributes"] = kept
	return rawState, nil
}

func redactedPrivateKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	return []string{redactedPrivateKey}
}
