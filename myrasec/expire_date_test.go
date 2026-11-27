package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// expireDateResources are the resources with a configurable expire_date, each with a config
// that passes the schema validation, the state attributes of that config (without them the
// plan is a replacement that diffs every attribute) and a function building the API object.
var expireDateResources = []struct {
	name   string
	config map[string]any
	state  map[string]string
	build  func(d *schema.ResourceData) (time.Time, error)
}{
	{
		name:   "myrasec_ip_filter",
		config: map[string]any{"subdomain_name": "www.example.com", "type": "BLACKLIST", "value": "192.0.2.1/32"},
		state:  map[string]string{"subdomain_name": "www.example.com", "type": "BLACKLIST", "value": "192.0.2.1/32"},
		build: func(d *schema.ResourceData) (time.Time, error) {
			filter, err := buildIPFilter(d)
			if err != nil {
				return time.Time{}, err
			}
			return filter.ExpireDate.Time, nil
		},
	},
	{
		name:   "myrasec_waf_rule",
		config: map[string]any{"subdomain_name": "www.example.com", "name": "rule", "direction": "in", "actions": wafRuleTestActions},
		state:  map[string]string{"subdomain_name": "www.example.com", "name": "rule", "direction": "in"},
		build: func(d *schema.ResourceData) (time.Time, error) {
			rule, err := buildWAFRule(d)
			if err != nil {
				return time.Time{}, err
			}
			return rule.ExpireDate.Time, nil
		},
	},
	{
		name:   "myrasec_tag_waf_rule",
		config: map[string]any{"tag_id": 1, "name": "rule", "direction": "in", "actions": wafRuleTestActions},
		state:  map[string]string{"tag_id": "1", "name": "rule", "direction": "in"},
		build: func(d *schema.ResourceData) (time.Time, error) {
			rule, err := buildTagWAFRule(d)
			if err != nil {
				return time.Time{}, err
			}
			return rule.ExpireDate.Time, nil
		},
	},
}

var wafRuleTestActions = []any{map[string]any{"type": "block"}}

func expireDateConfig(config map[string]any, expireDate string) *terraform.ResourceConfig {
	raw := map[string]any{"expire_date": expireDate}
	for k, v := range config {
		raw[k] = v
	}
	return terraform.NewResourceConfigRaw(raw)
}

// TestExpireDateOffsetWithoutColon covers a config that writes expire_date the way the API
// returns it (+0100 instead of +01:00): the value passes the validation, is sent as the same
// instant and causes no diff against the RFC3339 value in the state.
func TestExpireDateOffsetWithoutColon(t *testing.T) {
	const (
		stored  = "2027-01-01T12:00:00+01:00"
		compact = "2027-01-01T12:00:00+0100"
	)
	want := time.Date(2027, time.January, 1, 11, 0, 0, 0, time.UTC)
	provider := Provider()

	for _, tc := range expireDateResources {
		t.Run(tc.name, func(t *testing.T) {
			r := provider.ResourcesMap[tc.name]

			for _, value := range []string{stored, compact, ""} {
				if diags := provider.ValidateResource(tc.name, expireDateConfig(tc.config, value)); diags.HasError() {
					t.Errorf("validation rejected expire_date %q: %v", value, diags)
				}
			}
			if diags := provider.ValidateResource(tc.name, expireDateConfig(tc.config, "2027-01-01")); !diags.HasError() {
				t.Error("validation accepted an expire_date without a time")
			}

			d := r.TestResourceData()
			if err := d.Set("expire_date", compact); err != nil {
				t.Fatal(err)
			}
			got, err := tc.build(d)
			if err != nil {
				t.Fatalf("build failed: %v", err)
			}
			if !got.Equal(want) {
				t.Errorf("built expire date %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
			}

			state := &terraform.InstanceState{ID: "1", Attributes: map[string]string{"expire_date": stored}}
			for k, v := range tc.state {
				state.Attributes[k] = v
			}
			diff, err := r.Diff(context.Background(), state, expireDateConfig(tc.config, compact), nil)
			if err != nil {
				t.Fatal(err)
			}
			if diff != nil && (diff.RequiresNew() || diff.Attributes["expire_date"] != nil) {
				t.Errorf("same instant causes a diff: replacement=%v expire_date=%v", diff.RequiresNew(), diff.Attributes["expire_date"])
			}

			diff, err = r.Diff(context.Background(), state, expireDateConfig(tc.config, "2027-01-01T12:00:00+0200"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if diff == nil || diff.Attributes["expire_date"] == nil {
				t.Error("another instant causes no diff")
			}
		})
	}
}

// TestIPFilterCreateExpireDateOffsetWithoutColon runs the create with the offset written
// without the colon: the filter is sent with that expiry and the state holds the RFC3339 form.
func TestIPFilterCreateExpireDateOffsetWithoutColon(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/domain/1/ip-filters/ALL-1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if got := body["expireDate"]; got != "2027-01-01T12:00:00+0100" {
			t.Errorf("sent expireDate %v, want 2027-01-01T12:00:00+0100", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{ipFilterJSON(body["expireDate"])}})
	}))

	d := ipFilterResourceData(t)
	d.SetId("")
	if err := d.Set("expire_date", "2027-01-01T12:00:00+0100"); err != nil {
		t.Fatal(err)
	}
	if diags := resourceMyrasecIPFilterCreate(context.Background(), d, client); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if got := d.Get("expire_date"); got != "2027-01-01T12:00:00+01:00" {
		t.Errorf("expire_date = %q, want 2027-01-01T12:00:00+01:00", got)
	}
}

// TestIPFilterUpdateKeepsSuppressedExpireDate covers a filter whose state holds the RFC3339
// form while the config writes the offset without the colon, as after an import: the plan
// changes only the comment and the update sends the stored expiry.
func TestIPFilterUpdateKeepsSuppressedExpireDate(t *testing.T) {
	updates := 0
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/domain/1/ip-filters/ALL-1/1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		updates++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["expireDate"] != "2027-01-01T12:00:00+0100" || body["comment"] != "changed" {
			t.Errorf("sent expireDate=%v comment=%v", body["expireDate"], body["comment"])
		}
		filter := ipFilterJSON(body["expireDate"])
		filter["comment"] = body["comment"]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{filter}})
	}))

	r := resourceMyrasecIPFilter()
	state := &terraform.InstanceState{ID: "1", Attributes: map[string]string{
		"subdomain_name": "ALL-1", "domain_id": "1", "filter_id": "1", "type": "BLACKLIST", "value": "192.0.2.1",
		"enabled": "true", "comment": "", "created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z",
		"expire_date": "2027-01-01T12:00:00+01:00",
	}}
	config := terraform.NewResourceConfigRaw(map[string]any{
		"subdomain_name": "ALL-1", "type": "BLACKLIST", "value": "192.0.2.1", "comment": "changed",
		"expire_date": "2027-01-01T12:00:00+0100",
	})

	diff, err := r.Diff(context.Background(), state, config, client)
	if err != nil {
		t.Fatal(err)
	}
	if diff == nil || diff.RequiresNew() || diff.Attributes["comment"] == nil || diff.Attributes["expire_date"] != nil {
		t.Fatalf("plan must change the comment only: %v", diff)
	}

	next, diags := r.Apply(context.Background(), state, diff, client)
	if diags.HasError() {
		t.Fatalf("update failed: %v", diags)
	}
	if updates != 1 {
		t.Errorf("update was sent %d times, want 1", updates)
	}
	if next.Attributes["expire_date"] != "2027-01-01T12:00:00+01:00" || next.Attributes["comment"] != "changed" {
		t.Errorf("state after update: expire_date=%q comment=%q", next.Attributes["expire_date"], next.Attributes["comment"])
	}
}
