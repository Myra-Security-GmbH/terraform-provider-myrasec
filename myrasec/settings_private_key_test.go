package myrasec

import (
	"bytes"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
				var logs bytes.Buffer
				old := log.Writer()
				log.SetOutput(&logs)
				res.refresh(d, &response)
				log.SetOutput(old)
				if got := d.Get(settingsPrivateKey).(*schema.Set).List(); !reflect.DeepEqual(got, []any{"CONFIGURED_KEY"}) {
					t.Fatalf("refresh replaced configured key: %#v", got)
				}
				if strings.Contains(logs.String(), "SERVER_KEY") {
					t.Fatal("key leaked to logs")
				}
				imported := schema.TestResourceDataRaw(t, res.resource.Schema, map[string]any{})
				res.refresh(imported, &response)
				if imported.Get(settingsPrivateKey).(*schema.Set).Len() != 0 {
					t.Fatal("refresh imported server key")
				}
			}
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
