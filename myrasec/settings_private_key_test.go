package myrasec

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	ctyjson "github.com/hashicorp/go-cty/cty/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestSettingsPrivateKeyLifecycle(t *testing.T) {
	resources := []struct {
		name     string
		resource *schema.Resource
		build    func(*schema.ResourceData, bool) (map[string]any, error)
		refresh  func(*schema.ResourceData, any)
		envelope string
	}{
		{"subdomain", resourceMyrasecSettings(), buildSettings, func(d *schema.ResourceData, v any) { setSettingsData(d, v, "www.example.test", 1) }, "domain"},
		{"tag", resourceMyrasecTagSettings(), buildTagSettings, func(d *schema.ResourceData, v any) { setTagSettingsData(d, v, 1) }, "settings"},
	}
	for _, res := range resources {
		t.Run(res.name, func(t *testing.T) {
			if !res.resource.Schema[settingsPrivateKey].Sensitive {
				t.Fatal("private key must be sensitive")
			}
			for _, raw := range []any{nil, []any{redactedPrivateKey}, []any{"SERVER_KEY"}} {
				d := schema.TestResourceDataRaw(t, res.resource.Schema, map[string]any{settingsPrivateKey: []any{"CONFIGURED_KEY"}})
				response := map[string]any{res.envelope: map[string]any{settingsPrivateKey: raw, "only_https": true}}
				res.refresh(d, &response)
				if !d.Get("available_attributes").(*schema.Set).Contains(settingsPrivateKey) {
					t.Fatal("refresh dropped configured key from available_attributes")
				}
				if got := d.Get(settingsPrivateKey).(*schema.Set).List(); !reflect.DeepEqual(got, []any{"CONFIGURED_KEY"}) {
					t.Fatalf("refresh replaced configured key: %#v", got)
				}
				imported := schema.TestResourceDataRaw(t, res.resource.Schema, map[string]any{})
				res.refresh(imported, &response)
				if imported.Get(settingsPrivateKey).(*schema.Set).Len() != 0 {
					t.Fatal("refresh imported server key")
				}
			}
			t.Run("refresh_warning_without_key", func(t *testing.T) {
				d := schema.TestResourceDataRaw(t, res.resource.Schema, map[string]any{})
				response := map[string]any{res.envelope: map[string]any{settingsPrivateKey: []any{"SERVER_KEY"}, "only_https": "invalid_boolean"}}
				var logs bytes.Buffer
				old := log.Writer()
				log.SetOutput(&logs)
				defer log.SetOutput(old)
				res.refresh(d, &response)
				if !strings.Contains(logs.String(), "[WARN]") {
					t.Fatal("fixture did not exercise the warning path")
				}
				if strings.Contains(logs.String(), "SERVER_KEY") {
					t.Fatal("refresh exposed key material in logs")
				}
			})
			cases := []struct {
				name    string
				config  map[string]cty.Value
				values  []any
				clean   bool
				present bool
				want    any
			}{
				{"omitted", nil, nil, false, false, nil},
				{"replace", map[string]cty.Value{settingsPrivateKey: cty.SetVal([]cty.Value{cty.StringVal("NEW_KEY")})}, []any{"NEW_KEY"}, false, true, []string{"NEW_KEY"}},
				{"clear", map[string]cty.Value{settingsPrivateKey: cty.SetValEmpty(cty.String)}, []any{}, false, true, []string{}},
				{"destroy", nil, []any{"OLD_KEY"}, true, true, nil},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					d := configuredResourceData(res.resource, map[string]string{}, tc.config)
					if err := d.Set(settingsPrivateKey, tc.values); err != nil {
						t.Fatal(err)
					}
					var logs bytes.Buffer
					old := log.Writer()
					log.SetOutput(&logs)
					payload, err := res.build(d, tc.clean)
					log.SetOutput(old)
					if err != nil {
						t.Fatal(err)
					}
					value, present := payload[settingsPrivateKey]
					if present != tc.present || !reflect.DeepEqual(value, tc.want) {
						t.Fatalf("key payload = %#v, present %t", value, present)
					}
					if strings.Contains(logs.String(), "NEW_KEY") {
						t.Fatal("key leaked while building payload")
					}
				})
			}
		})
	}
}

func TestPrivateKeyDataSourceRedaction(t *testing.T) {
	for _, keys := range [][]string{nil, {}, {"SERVER_KEY"}, {redactedPrivateKey}, {"FIRST", "SECOND"}} {
		got := redactedPrivateKeys(keys)
		if len(keys) == 0 {
			if len(got) != 0 {
				t.Fatal("empty keys must remain empty")
			}
		} else if !reflect.DeepEqual(got, []string{redactedPrivateKey}) {
			t.Fatal("data source must return only the marker")
		}
	}
	for _, resource := range []*schema.Resource{dataSourceMyrasecSettings(), dataSourceMyrasecTagSettings()} {
		sensitive := false
		for _, field := range resource.Schema {
			if nested, ok := field.Elem.(*schema.Resource); ok && nested.Schema[settingsPrivateKey] != nil {
				sensitive = nested.Schema[settingsPrivateKey].Sensitive
			}
		}
		if !sensitive {
			t.Fatal("nested private key must be sensitive")
		}
	}
}

func TestSettingsCertificatePairPlanApplyRefresh(t *testing.T) {
	variants := []struct {
		name     string
		resource func() *schema.Resource
		base     map[string]any
		build    func(*schema.ResourceData, bool) (map[string]any, error)
		refresh  func(*schema.ResourceData, map[string]any)
	}{
		{"subdomain", resourceMyrasecSettings, map[string]any{"subdomain_name": "www.example.test"}, buildSettings, func(d *schema.ResourceData, v map[string]any) {
			response := map[string]any{"domain": v}
			setSettingsData(d, &response, "www.example.test", 1)
		}},
		{"tag", resourceMyrasecTagSettings, map[string]any{"tag_id": 1}, buildTagSettings, func(d *schema.ResourceData, v map[string]any) {
			response := map[string]any{"settings": v}
			setTagSettingsData(d, &response, 1)
		}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			r := v.resource()
			ctx := context.Background()
			remote := map[string]any{}
			var payload map[string]any
			apply := func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
				var err error
				payload, err = v.build(d, false)
				if err != nil {
					return diag.FromErr(err)
				}
				for name, value := range payload {
					if value == nil {
						delete(remote, name)
					} else {
						remote[name] = value
					}
				}
				// Convert arrays to the same generic JSON types returned by the API.
				wireBytes, _ := json.Marshal(remote)
				var wire map[string]any
				if err := json.Unmarshal(wireBytes, &wire); err != nil {
					return diag.FromErr(err)
				}
				if keys, ok := wire[settingsPrivateKey].([]any); ok && len(keys) > 0 {
					wire[settingsPrivateKey] = []any{redactedPrivateKey}
				}
				d.SetId("1")
				v.refresh(d, wire)
				return nil
			}
			r.CreateContext = apply
			r.UpdateContext = apply
			config := map[string]any{}
			for name, value := range v.base {
				config[name] = value
			}
			config["only_https"] = true
			var state *terraform.InstanceState

			plan := func() (*terraform.InstanceDiff, error) {
				// The protocol normally supplies RawConfig on priorState before Diff.
				rawBytes, _ := json.Marshal(config)
				var raw ctyjson.SimpleJSONValue
				if err := raw.UnmarshalJSON(rawBytes); err != nil {
					return nil, err
				}
				value, err := r.CoreConfigSchema().CoerceValue(raw.Value)
				if err != nil {
					return nil, err
				}
				if state == nil {
					state = &terraform.InstanceState{}
				}
				state.RawConfig = value
				return r.Diff(ctx, state, terraform.NewResourceConfigRaw(config), nil)
			}
			runApply := func() {
				t.Helper()
				diff, err := plan()
				if err != nil {
					t.Fatal(err)
				}
				if diff == nil || diff.Empty() {
					t.Fatal("expected a planned change")
				}
				var diagnostics diag.Diagnostics
				state, diagnostics = r.Apply(ctx, state, diff, nil)
				if diagnostics.HasError() {
					t.Fatal(diagnostics)
				}
			}
			converges := func() {
				t.Helper()
				diff, err := plan()
				if err != nil {
					t.Fatal(err)
				}
				if diff != nil && !diff.Empty() {
					t.Fatalf("plan did not converge after refresh: %#v", diff.Attributes)
				}
			}
			imported := r.Data(&terraform.InstanceState{ID: "1"})
			v.refresh(imported, map[string]any{settingsCertificate: []any{"UNMANAGED_CERT"}, settingsPrivateKey: []any{redactedPrivateKey}})
			for _, name := range []string{settingsCertificate, settingsPrivateKey} {
				if imported.Get(name).(*schema.Set).Len() != 0 || imported.Get("available_attributes").(*schema.Set).Contains(name) {
					t.Fatalf("import unexpectedly took ownership of %s", name)
				}
			}
			remote[settingsCertificate] = []string{"UNMANAGED_CERT"}
			remote[settingsPrivateKey] = []string{"UNMANAGED_KEY"}
			runApply()
			converges()
			config["only_https"] = false
			runApply()
			converges()
			for _, name := range []string{settingsPrivateKey, settingsCertificate} {
				if _, present := payload[name]; present {
					t.Fatalf("unmanaged pair member %s was sent", name)
				}
			}
			if !reflect.DeepEqual(remote[settingsPrivateKey], []string{"UNMANAGED_KEY"}) || !reflect.DeepEqual(remote[settingsCertificate], []string{"UNMANAGED_CERT"}) {
				t.Fatal("unmanaged pair changed")
			}
			config["only_https"] = true
			config[settingsCertificate] = []any{"CERTIFICATE"}
			config[settingsPrivateKey] = []any{"PRIVATE_KEY"}
			runApply()
			converges()
			config["only_https"] = false
			runApply()
			converges()
			if !reflect.DeepEqual(remote[settingsPrivateKey], []string{"PRIVATE_KEY"}) {
				t.Fatal("unrelated settings save lost the key")
			}
			delete(config, settingsPrivateKey)
			runApply()
			converges()
			if key, present := payload[settingsPrivateKey]; !present || key != nil {
				t.Fatal("removing the configured key must send null")
			}
			if _, ok := remote[settingsPrivateKey]; ok {
				t.Fatal("removed key still overrides inheritance")
			}
			config[settingsPrivateKey] = []any{"REPLACEMENT"}
			runApply()
			converges()
			delete(config, settingsPrivateKey)
			delete(config, settingsCertificate)
			runApply()
			converges()
			for _, name := range []string{settingsPrivateKey, settingsCertificate} {
				if value, present := payload[name]; !present || value != nil {
					t.Fatalf("removed pair member %s must send null", name)
				}
				if _, ok := remote[name]; ok {
					t.Fatalf("removed pair member %s still overrides inheritance", name)
				}
			}
			config["only_https"] = true
			runApply()
			converges()
			for _, name := range []string{settingsPrivateKey, settingsCertificate} {
				if _, present := payload[name]; present {
					t.Fatalf("unmanaged pair member %s must be omitted", name)
				}
			}
			config[settingsCertificate] = []any{"CERTIFICATE"}
			config[settingsPrivateKey] = []any{}
			runApply()
			converges()
			if !reflect.DeepEqual(payload[settingsPrivateKey], []string{}) {
				t.Fatal("explicit empty key must send []")
			}
			delete(config, settingsPrivateKey)
			// An unrelated change causes an update even where the SDK equates an empty set and omission.
			config["only_https"] = false
			runApply()
			converges()
			if key, present := payload[settingsPrivateKey]; !present || key != nil {
				t.Fatal("omitted key with configured certificate must restore inheritance")
			}
		})
	}
}
