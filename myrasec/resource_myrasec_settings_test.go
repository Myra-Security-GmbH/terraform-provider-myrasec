package myrasec

import (
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestSettingsBoolValue(t *testing.T) {
	tests := []struct {
		name    string
		setting string
		value   bool
		want    any
	}{
		{"ip_lock true", "ip_lock", true, "yes"},
		{"ip_lock false", "ip_lock", false, "no"},
		{"other setting true", "ipv6_active", true, true},
		{"other setting false", "ipv6_active", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := settingsBoolValue(tt.setting, tt.value); got != tt.want {
				t.Errorf("settingsBoolValue(%q, %v) = %#v, want %#v", tt.setting, tt.value, got, tt.want)
			}
		})
	}
}

// configuredResourceData returns resource data whose state attributes and raw config both
// carry the passed values. buildSettings takes the value from the state and the "is it
// configured" decision from the raw config, so both are filled. Every attribute missing
// from config is null in the raw config. The helper cannot express a state that differs
// from the config, a regression that sends the prior state value instead of the planned
// one is not caught here.
func configuredResourceData(r *schema.Resource, attributes map[string]string, config map[string]cty.Value) *schema.ResourceData {
	ty := r.CoreConfigSchema().ImpliedType()
	raw := make(map[string]cty.Value, len(ty.AttributeTypes()))
	for name, attrType := range ty.AttributeTypes() {
		if v, ok := config[name]; ok {
			raw[name] = v
		} else {
			raw[name] = cty.NullVal(attrType)
		}
	}

	return r.Data(&terraform.InstanceState{Attributes: attributes, RawConfig: cty.ObjectVal(raw)})
}

// TestBuildSettingsPayloadIPLock checks the update payload of both settings resources:
// ip_lock goes out as the yes/no string the API expects, an unconfigured ip_lock is sent
// as null so the API removes the stored value, other booleans stay JSON booleans and the
// clean payload of a delete nulls everything.
func TestBuildSettingsPayloadIPLock(t *testing.T) {
	resources := []struct {
		name     string
		resource *schema.Resource
		base     map[string]string
		baseCfg  map[string]cty.Value
		build    func(*schema.ResourceData, bool) (map[string]any, error)
	}{
		{
			name:     "settings",
			resource: resourceMyrasecSettings(),
			base:     map[string]string{"subdomain_name": "ALL-1"},
			baseCfg:  map[string]cty.Value{"subdomain_name": cty.StringVal("ALL-1")},
			build:    buildSettings,
		},
		{
			name:     "tag settings",
			resource: resourceMyrasecTagSettings(),
			base:     map[string]string{"tag_id": "1"},
			baseCfg:  map[string]cty.Value{"tag_id": cty.NumberIntVal(1)},
			build:    buildTagSettings,
		},
	}

	tests := []struct {
		name      string
		ipLock    *bool
		clean     bool
		wantLock  any
		wantOther any
	}{
		{name: "ip_lock true", ipLock: ptr(true), wantLock: "yes", wantOther: false},
		{name: "ip_lock false", ipLock: ptr(false), wantLock: "no", wantOther: false},
		{name: "ip_lock not configured", wantLock: nil, wantOther: false},
		{name: "clean payload nulls ip_lock", ipLock: ptr(true), clean: true, wantLock: nil, wantOther: nil},
	}

	for _, res := range resources {
		for _, tt := range tests {
			t.Run(res.name+" "+tt.name, func(t *testing.T) {
				attributes := map[string]string{"ipv6_active": "false"}
				config := map[string]cty.Value{"ipv6_active": cty.False}
				for k, v := range res.base {
					attributes[k] = v
				}
				for k, v := range res.baseCfg {
					config[k] = v
				}
				if tt.ipLock != nil {
					attributes["ip_lock"] = map[bool]string{true: "true", false: "false"}[*tt.ipLock]
					config["ip_lock"] = cty.BoolVal(*tt.ipLock)
				}

				payload, err := res.build(configuredResourceData(res.resource, attributes, config), tt.clean)
				if err != nil {
					t.Fatalf("build: %v", err)
				}

				if got, ok := payload["ip_lock"]; !ok || got != tt.wantLock {
					t.Errorf("ip_lock = %#v (present %v), want %#v", got, ok, tt.wantLock)
				}
				if got, ok := payload["ipv6_active"]; !ok || got != tt.wantOther {
					t.Errorf("ipv6_active = %#v (present %v), want %#v", got, ok, tt.wantOther)
				}
				if got, ok := payload["image_optimization"]; !ok || got != nil {
					t.Errorf("image_optimization = %#v (present %v), want nil", got, ok)
				}
			})
		}
	}
}

func ptr[T any](v T) *T {
	return &v
}
