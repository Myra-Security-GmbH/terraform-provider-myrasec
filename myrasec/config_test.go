package myrasec

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestValidateAPIBaseURL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		url      string
		insecure bool
		wantErr  string
	}{
		{name: "https", url: "https://api.example.com/%s"},
		{name: "https with port and path", url: "https://api.example.com:8443/v2/%s"},
		{name: "http localhost", url: "http://localhost:8080/%s"},
		{name: "http loopback IPv4", url: "http://127.0.0.1/%s"},
		{name: "http loopback IPv6", url: "http://[::1]:8080/%s"},
		{name: "http other host", url: "http://api.example.com/%s", wantErr: "plain http"},
		{name: "http other host with opt-in", url: "http://api.example.com/%s", insecure: true},
		{name: "missing placeholder", url: "https://api.example.com/", wantErr: "%s placeholder"},
		{name: "missing host", url: "https:///%s", wantErr: "name a host"},
		{name: "other scheme", url: "ftp://api.example.com/%s", wantErr: "scheme"},
		{name: "opt-in does not allow other schemes", url: "ftp://api.example.com/%s", insecure: true, wantErr: "scheme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAPIBaseURL(tc.url, tc.insecure)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestConfigValidateRejectsPlainHTTP(t *testing.T) {
	config := Config{APIToken: "token", APIBaseURL: "http://api.example.com/%s"}
	if err := config.validate(); err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("plain http was accepted: %v", err)
	}

	config.AllowInsecureHTTP = true
	if err := config.validate(); err != nil {
		t.Fatalf("insecure opt-in was ignored: %v", err)
	}
}

// TestProviderConfigureInsecure covers the provider attribute end to end: a plain http base
// URL fails the provider configuration unless allow_insecure_http is set.
func TestProviderConfigureInsecure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		insecure bool
		wantErr  bool
	}{
		{name: "refused by default", wantErr: true},
		{name: "allowed with opt-in", insecure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := Provider()
			d := schema.TestResourceDataRaw(t, provider.Schema, map[string]any{
				"api_token":           "token",
				"api_base_url":        "http://api.example.com/%s",
				"allow_insecure_http": tc.insecure,
			})

			client, diags := providerConfigure(context.Background(), d)
			if diags.HasError() != tc.wantErr {
				t.Fatalf("error = %v, want error %v", diags, tc.wantErr)
			}
			if !tc.wantErr && client == nil {
				t.Fatal("no client returned")
			}
		})
	}
}
