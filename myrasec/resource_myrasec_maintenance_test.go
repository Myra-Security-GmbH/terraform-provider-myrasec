package myrasec

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestMaintenanceCreateWithUTCZDate(t *testing.T) {
	res := resourceMyrasecMaintenance()

	start := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().Add(720 * time.Hour).UTC().Format(time.RFC3339)

	cfg := terraform.NewResourceConfigRaw(map[string]any{
		"subdomain_name": "www.example.com",
		"content":        "<html><body>Maintenance</body></html>",
		"start":          start,
		"end":            end,
	})

	if _, err := res.Diff(context.Background(), nil, cfg, nil); err != nil {
		t.Fatalf("unexpected diff error: %v", err)
	}
}

func TestMaintenanceCreateWithUnknownEnd(t *testing.T) {
	res := resourceMyrasecMaintenance()

	cfg := terraform.NewResourceConfigRaw(map[string]any{
		"subdomain_name": "www.example.com",
		"content":        "<html><body>Maintenance</body></html>",
		"start":          time.Now().UTC().Format(time.RFC3339),
		"end":            "",
	})

	if _, err := res.Diff(context.Background(), nil, cfg, nil); err != nil {
		t.Fatalf("unexpected diff error: %v", err)
	}
}
