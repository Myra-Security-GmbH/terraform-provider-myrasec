package myrasec

import (
	"testing"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
)

// TestSetApiKeyDataKeepsSecret covers the secret the API returns only once: a later read
// without the secret must not overwrite the stored value.
func TestSetApiKeyDataKeepsSecret(t *testing.T) {
	now := &types.DateTime{Time: time.Now()}
	d := resourceMyrasecApiKey().TestResourceData()

	setApiKeyData(d, &myrasec.APIKey{ID: 1, Name: "key", Key: "public", Secret: "created-once", Created: now, Modified: now})
	if d.Get("secret") != "created-once" {
		t.Fatalf("secret after create = %q", d.Get("secret"))
	}

	setApiKeyData(d, &myrasec.APIKey{ID: 1, Name: "key", Key: "public", Created: now, Modified: now})
	if d.Get("secret") != "created-once" {
		t.Errorf("secret after read = %q, want the created value", d.Get("secret"))
	}
}
