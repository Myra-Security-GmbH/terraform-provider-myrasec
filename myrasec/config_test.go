package myrasec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
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

// TestClientInsecureHTTP sends a request through the configured client: the client itself
// refuses a plain http base URL on a host other than the local machine unless the opt-in
// reaches it.
func TestClientInsecureHTTP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		insecure bool
	}{
		{name: "refused"},
		{name: "allowed with opt-in", insecure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"error": false, "page": 1, "pageSize": 250, "count": 1, "data": [{"id": 1, "name": "example.com"}]}`))
			}))
			t.Cleanup(server.Close)

			client, err := (Config{APIToken: "token", Language: "en", APIBaseURL: "http://api.example.com/%s", AllowInsecureHTTP: tc.insecure}).Client()
			if err != nil {
				t.Fatal(err)
			}
			// Every connection lands on the test server, the URL keeps its non-loopback host.
			err = client.SetHTTPClient(&http.Client{Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				},
			}})
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.ListDomainsContext(context.Background(), nil)
			if tc.insecure {
				if err != nil || hits.Load() != 1 {
					t.Fatalf("request with opt-in failed: err=%v hits=%d", err, hits.Load())
				}
				return
			}
			if !errors.Is(err, myrasec.ErrInsecureEndpoint) || hits.Load() != 0 {
				t.Fatalf("plain http was not refused: err=%v hits=%d", err, hits.Load())
			}
		})
	}
}

// TestProviderConfigureInsecure covers the provider attribute end to end: a plain http base
// URL fails the provider configuration unless allow_insecure_http is set, in the
// configuration or through the environment.
func TestProviderConfigureInsecure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		insecure bool
		env      string
		wantErr  bool
	}{
		{name: "refused by default", wantErr: true},
		{name: "allowed with opt-in", insecure: true},
		{name: "allowed through the environment", env: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MYRASEC_ALLOW_INSECURE_HTTP", tc.env)
			raw := map[string]any{
				"api_token":    "token",
				"api_base_url": "http://api.example.com/%s",
			}
			if tc.env == "" {
				raw["allow_insecure_http"] = tc.insecure
			}

			provider := Provider()
			d := schema.TestResourceDataRaw(t, provider.Schema, raw)

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
