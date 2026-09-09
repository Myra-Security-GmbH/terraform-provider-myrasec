package myrasec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const unknownConfigValue = "74D93920-ED26-11E3-AC10-0800200C9A66"

func diffMaintenance(t *testing.T, start, end any) error {
	t.Helper()

	res := resourceMyrasecMaintenance()
	cfg := terraform.NewResourceConfigRaw(map[string]any{
		"subdomain_name": "www.example.com",
		"content":        "<html><body>Maintenance</body></html>",
		"start":          start,
		"end":            end,
	})

	_, err := res.Diff(context.Background(), nil, cfg, nil)
	return err
}

func TestMaintenanceDiffUnknownEndDoesNotPanic(t *testing.T) {
	start := time.Now().UTC().Format(time.RFC3339)

	if err := diffMaintenance(t, start, unknownConfigValue); err != nil {
		t.Fatalf("unexpected diff error: %v", err)
	}
}

func TestMaintenanceDiffUnknownStartDoesNotPanic(t *testing.T) {
	end := time.Now().Add(720 * time.Hour).UTC().Format(time.RFC3339)

	if err := diffMaintenance(t, unknownConfigValue, end); err != nil {
		t.Fatalf("unexpected diff error: %v", err)
	}
}

func TestMaintenanceDiffPastEndOnCreate(t *testing.T) {
	start := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	err := diffMaintenance(t, start, end)
	if err == nil || !strings.Contains(err.Error(), "can not be created in the past") {
		t.Fatalf("expected past-date error, got: %v", err)
	}
}

func TestMaintenanceDiffEndBeforeStart(t *testing.T) {
	start := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	err := diffMaintenance(t, start, end)
	if err == nil || !strings.Contains(err.Error(), "end date should not be before start date") {
		t.Fatalf("expected end-before-start error, got: %v", err)
	}
}

func TestMaintenanceDiffUnknownStartPastEndStillRejected(t *testing.T) {
	end := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	err := diffMaintenance(t, unknownConfigValue, end)
	if err == nil || !strings.Contains(err.Error(), "can not be created in the past") {
		t.Fatalf("expected past-date error with unknown start, got: %v", err)
	}
}
