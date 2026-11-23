package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// settingsResetServer answers the requests a settings destroy makes and records the paths of the
// reset writes. tagID is the tag the GET /tags/{id} lookup answers for tag settings.
type settingsResetServer struct {
	t      *testing.T
	writes []string
}

func (s *settingsResetServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/domain/1/www.example.com/settings",
		r.Method == http.MethodPut && r.URL.Path == "/tag/5/settings":
		s.writes = append(s.writes, r.Method+" "+r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{map[string]any{}}})
	case r.Method == http.MethodGet && r.URL.Path == "/tags/5":
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{
			map[string]any{"id": 5, "name": "tag", "type": "CONFIG", "created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z"},
		}})
	default:
		s.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestSettingsDestroyAcceptsEveryID pins the destroy of myrasec_settings for both ID formats the
// resource can have in the state: create and update set a Unix timestamp, an import keeps the
// subdomain name it was imported with (ImportStatePassthroughContext). The destroy resets the
// settings of subdomain_name and must not depend on the ID being numeric.
func TestSettingsDestroyAcceptsEveryID(t *testing.T) {
	for _, id := range []string{"1788873184", "www.example.com"} {
		t.Run(id, func(t *testing.T) {
			srv := &settingsResetServer{t: t}
			client := domainTestClient(t, srv)

			d := resourceMyrasecSettings().TestResourceData()
			d.SetId(id)
			for k, v := range map[string]any{"subdomain_name": "www.example.com", "domain_id": 1} {
				if err := d.Set(k, v); err != nil {
					t.Fatal(err)
				}
			}

			if diags := resourceMyrasecSettingsDelete(context.Background(), d, client); diags.HasError() {
				t.Fatalf("destroy failed: %v", diags)
			}
			if len(srv.writes) != 1 || srv.writes[0] != "POST /domain/1/www.example.com/settings" {
				t.Errorf("reset writes = %v, want exactly the settings of www.example.com", srv.writes)
			}
		})
	}
}

// TestTagSettingsDestroyAcceptsEveryID is the same for myrasec_tag_settings: the destroy resets
// the settings of tag_id and must not depend on the ID being numeric.
func TestTagSettingsDestroyAcceptsEveryID(t *testing.T) {
	for _, id := range []string{"1788873184", "imported-tag-settings"} {
		t.Run(id, func(t *testing.T) {
			srv := &settingsResetServer{t: t}
			client := domainTestClient(t, srv)

			d := resourceMyrasecTagSettings().TestResourceData()
			d.SetId(id)
			if err := d.Set("tag_id", 5); err != nil {
				t.Fatal(err)
			}

			if diags := resourceMyrasecTagSettingsDelete(context.Background(), d, client); diags.HasError() {
				t.Fatalf("destroy failed: %v", diags)
			}
			if len(srv.writes) != 1 || srv.writes[0] != "PUT /tag/5/settings" {
				t.Errorf("reset writes = %v, want exactly the settings of tag 5", srv.writes)
			}
		})
	}
}
