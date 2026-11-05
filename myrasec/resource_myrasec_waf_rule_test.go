package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestWAFRuleReadFlags pins the attributes the read copies from the API: the expiry date
// (unset dates become an empty string, set dates keep their offset) and the sync flag.
func TestWAFRuleReadFlags(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expireDate any
		want       string
	}{
		{name: "unset expiry", expireDate: nil, want: ""},
		{name: "set expiry", expireDate: "2027-01-01T00:00:00+0100", want: "2027-01-01T00:00:00+01:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/domain/1/waf-rules" || r.URL.Query().Get("subDomain") != "www.example.com." {
					t.Errorf("unexpected request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
				}
				rule := map[string]any{
					"id": 7, "name": "rule", "direction": "in", "sort": 1, "sync": true,
					"processNext": false, "enabled": true, "ruleType": "domain", "subDomainName": "www.example.com.",
					"created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z", "expireDate": tc.expireDate,
					"conditions": []any{}, "actions": []any{},
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{rule}})
			}))

			d := resourceMyrasecWAFRule().TestResourceData()
			d.SetId("7")
			for k, v := range map[string]any{"subdomain_name": "www.example.com", "domain_id": 1, "expire_date": "2020-01-01T00:00:00Z"} {
				if err := d.Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			if diags := resourceMyrasecWAFRuleRead(context.Background(), d, client); diags.HasError() {
				t.Fatal(diags)
			}
			if got := d.Get("expire_date"); got != tc.want {
				t.Errorf("expire_date = %q, want %q", got, tc.want)
			}
			if d.Get("sync") != true {
				t.Errorf("sync=%v, want true", d.Get("sync"))
			}
		})
	}
}

func TestBuildWAFRuleSendsFlags(t *testing.T) {
	d := resourceMyrasecWAFRule().TestResourceData()
	for k, v := range map[string]any{"subdomain_name": "www.example.com", "name": "rule", "direction": "in", "sync": true} {
		if err := d.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	rule, err := buildWAFRule(d)
	if err != nil {
		t.Fatal(err)
	}
	if !rule.Sync {
		t.Errorf("sync=%v, want true", rule.Sync)
	}
}

// TestWAFRuleReadGoneClearsID covers a rule that was deleted outside Terraform: the read drops
// it from the state without an error so the next apply recreates it.
func TestWAFRuleReadGoneClearsID(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{}})
	}))

	d := resourceMyrasecWAFRule().TestResourceData()
	d.SetId("7")
	for k, v := range map[string]any{"subdomain_name": "www.example.com", "domain_id": 1} {
		if err := d.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if diags := resourceMyrasecWAFRuleRead(context.Background(), d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if d.Id() != "" {
		t.Errorf("ID %q was kept for a rule the API no longer lists", d.Id())
	}
}

// TestTagWAFRuleImportMissing covers the import of a rule the API does not list: the import
// fails instead of creating a state entry for a rule that does not exist.
func TestTagWAFRuleImportMissing(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/tags/5":
			_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{tagJSON(5)}})
		case "/tag/5/waf-rules":
			_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{}})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	r := resourceMyrasecTagWAFRule()
	d := r.TestResourceData()
	d.SetId("5:999")
	result, err := r.Importer.StateContext(context.Background(), d, client)
	if err == nil {
		t.Fatalf("import of a missing rule succeeded: %v", result)
	}
}
