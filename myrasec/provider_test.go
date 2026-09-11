package myrasec

import "testing"

// TestProviderInternalValidate runs the schema validation the SDK performs before the
// first plan. A defect here breaks every user of the provider, so it has to fail in CI.
func TestProviderInternalValidate(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("provider schema is invalid: %v", err)
	}
}
