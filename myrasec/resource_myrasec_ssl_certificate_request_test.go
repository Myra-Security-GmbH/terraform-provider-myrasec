package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestSSLCertificateRequestInternalValidate(t *testing.T) {
	if err := resourceMyrasecSSLCertificateRequest().InternalValidate(nil, true); err != nil {
		t.Fatalf("resource schema invalid: %v", err)
	}
	if err := dataSourceMyrasecSSLCertificateRequests().InternalValidate(nil, false); err != nil {
		t.Fatalf("data source schema invalid: %v", err)
	}
	if err := dataSourceMyrasecSSLCertificateRequestDomainChecks().InternalValidate(nil, false); err != nil {
		t.Fatalf("domain checks data source schema invalid: %v", err)
	}
}

func TestBuildSSLCertificateRequest(t *testing.T) {
	d := resourceMyrasecSSLCertificateRequest().TestResourceData()

	d.Set("certificate_provider", "SECTIGO")
	d.Set("algorithm", "RSA4096")
	d.Set("subject_alternative_names", []any{"www.example.com", "*.example.org"})
	d.Set("subdomains", []any{"www.example.com"})
	d.Set("ssl_provider_credentials_id", 42)
	d.Set("renewal_interval", 30)
	d.Set("signature_algorithm", "SHA384")
	d.Set("include_cross_signed_roots", true)

	request := buildSSLCertificateRequest(d)

	if request.ID != 0 {
		t.Errorf("ID = %d, want 0 on build", request.ID)
	}
	if request.Provider != "SECTIGO" {
		t.Errorf("Provider = %q, want SECTIGO", request.Provider)
	}
	if request.Algorithm != "RSA4096" {
		t.Errorf("Algorithm = %q, want RSA4096", request.Algorithm)
	}
	if request.SSLProviderCredentialsID != 42 {
		t.Errorf("SSLProviderCredentialsID = %d, want 42", request.SSLProviderCredentialsID)
	}
	if request.RenewalInterval != 30 {
		t.Errorf("RenewalInterval = %d, want 30", request.RenewalInterval)
	}
	if request.SignatureAlgorithm != "SHA384" {
		t.Errorf("SignatureAlgorithm = %q, want SHA384", request.SignatureAlgorithm)
	}
	if !request.IncludeCrossSignedRoots {
		t.Error("IncludeCrossSignedRoots = false, want true")
	}

	names := make(map[string]bool)
	for _, san := range request.SubjectAlternativeNames {
		names[san.Name] = true
	}
	if len(names) != 2 || !names["www.example.com"] || !names["*.example.org"] {
		t.Errorf("SubjectAlternativeNames = %v, want www.example.com and *.example.org", request.SubjectAlternativeNames)
	}

	if len(request.Assignments) != 1 || request.Assignments[0].SubDomainName != "www.example.com" {
		t.Errorf("Assignments = %v, want www.example.com", request.Assignments)
	}
}

func TestBuildSSLCertificateRequestEmptyCollections(t *testing.T) {
	d := resourceMyrasecSSLCertificateRequest().TestResourceData()

	d.Set("certificate_provider", "LETS_ENCRYPT")
	d.Set("algorithm", "ECDSA256")

	request := buildSSLCertificateRequest(d)

	if request.SubjectAlternativeNames == nil {
		t.Error("SubjectAlternativeNames should be an empty slice, not nil")
	}
	if request.Assignments == nil {
		t.Error("Assignments should be an empty slice, not nil")
	}
}

func TestKeepSSLCertificateRequestIDs(t *testing.T) {
	date := func(value string) *types.DateTime {
		t.Helper()
		dt, err := types.ParseDate(value)
		if err != nil {
			t.Fatalf("invalid test date %q: %v", value, err)
		}
		return dt
	}

	sanCreated, sanModified := date("2026-09-01T10:00:00+02:00"), date("2026-09-02T11:00:00+02:00")
	wildcardCreated, wildcardModified := date("2026-09-03T12:00:00+02:00"), date("2026-09-04T13:00:00+02:00")
	assignmentCreated, assignmentModified := date("2026-09-05T14:00:00+02:00"), date("2026-09-06T15:00:00+02:00")

	current := &myrasec.SSLCertificateRequest{
		SubjectAlternativeNames: []myrasec.SSLCertificateRequestSAN{
			{ID: 10, Name: "www.example.com", Created: sanCreated, Modified: sanModified},
			{ID: 11, Name: "*.example.org", Created: wildcardCreated, Modified: wildcardModified},
		},
		Assignments: []myrasec.SSLCertificateRequestAssignment{
			{ID: 20, SubDomainName: "www.example.com", Created: assignmentCreated, Modified: assignmentModified},
			{ID: 21, SubDomainName: "old.example.com", Created: date("2026-09-07T16:00:00+02:00"), Modified: date("2026-09-08T17:00:00+02:00")},
		},
	}

	request := &myrasec.SSLCertificateRequest{
		SubjectAlternativeNames: []myrasec.SSLCertificateRequestSAN{
			{Name: "WWW.Example.com."},
			{Name: "*.example.org"},
			{Name: "new.example.com"},
		},
		Assignments: []myrasec.SSLCertificateRequestAssignment{
			{SubDomainName: "WWW.Example.com."},
			{SubDomainName: "new.example.com"},
		},
	}

	keepSSLCertificateRequestIDs(request, current)

	// Entries removed from the configuration (old.example.com) must not come back. A kept entry
	// carries the timestamps of the stored one: the API rejects an entry sent with an ID but
	// without its modified timestamp. A new entry carries neither ID nor timestamps.
	wantSANs := []myrasec.SSLCertificateRequestSAN{
		{ID: 10, Name: "WWW.Example.com.", Created: sanCreated, Modified: sanModified},
		{ID: 11, Name: "*.example.org", Created: wildcardCreated, Modified: wildcardModified},
		{ID: 0, Name: "new.example.com"},
	}
	if len(request.SubjectAlternativeNames) != len(wantSANs) {
		t.Fatalf("SubjectAlternativeNames = %+v, want %d entries", request.SubjectAlternativeNames, len(wantSANs))
	}
	for i, want := range wantSANs {
		got := request.SubjectAlternativeNames[i]
		if got.ID != want.ID || got.Name != want.Name ||
			formatDateTime(got.Created) != formatDateTime(want.Created) || formatDateTime(got.Modified) != formatDateTime(want.Modified) {
			t.Errorf("SubjectAlternativeNames[%d] = %+v, want %+v", i, got, want)
		}
	}

	wantAssignments := []myrasec.SSLCertificateRequestAssignment{
		{ID: 20, SubDomainName: "WWW.Example.com.", Created: assignmentCreated, Modified: assignmentModified},
		{ID: 0, SubDomainName: "new.example.com"},
	}
	if len(request.Assignments) != len(wantAssignments) {
		t.Fatalf("Assignments = %+v, want %d entries", request.Assignments, len(wantAssignments))
	}
	for i, want := range wantAssignments {
		got := request.Assignments[i]
		if got.ID != want.ID || got.SubDomainName != want.SubDomainName ||
			formatDateTime(got.Created) != formatDateTime(want.Created) || formatDateTime(got.Modified) != formatDateTime(want.Modified) {
			t.Errorf("Assignments[%d] = %+v, want %+v", i, got, want)
		}
	}
}

func TestFindRedundantSAN(t *testing.T) {
	tests := []struct {
		name         string
		names        []string
		wantName     string
		wantWildcard string
	}{
		{
			name:  "no wildcard",
			names: []string{"www.example.com", "api.example.com"},
		},
		{
			name:  "wildcard without covered name",
			names: []string{"*.example.com", "example.com", "a.b.example.com"},
		},
		{
			name:         "covered name",
			names:        []string{"*.example.com", "www.example.com"},
			wantName:     "www.example.com",
			wantWildcard: "*.example.com",
		},
		{
			name:         "covered name with different case",
			names:        []string{"*.Example.com", "www.example.com"},
			wantName:     "www.example.com",
			wantWildcard: "*.example.com",
		},
		{
			name:  "wildcard of another domain",
			names: []string{"*.example.org", "www.example.com"},
		},
		{
			name:         "wildcard with trailing dot",
			names:        []string{"*.example.com.", "www.example.com"},
			wantName:     "www.example.com",
			wantWildcard: "*.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, wildcard := findRedundantSAN(tt.names)
			if name != tt.wantName || wildcard != tt.wantWildcard {
				t.Errorf("findRedundantSAN() = (%q, %q), want (%q, %q)", name, wildcard, tt.wantName, tt.wantWildcard)
			}
		})
	}
}

func TestSSLCertificateRequestCustomizeDiff(t *testing.T) {
	// sectigoState is the state of a Sectigo request with every provider specific attribute set
	sectigoState := &terraform.InstanceState{
		ID: "1",
		Attributes: map[string]string{
			"id":                          "1",
			"request_id":                  "1",
			"certificate_provider":        "SECTIGO",
			"algorithm":                   "RSA2048",
			"subject_alternative_names.#": "1",
			"subject_alternative_names." + strconv.Itoa(hashDomainName("www.example.com")): "www.example.com",
			"ssl_provider_credentials_id": "7",
			"renewal_interval":            "30",
			"signature_algorithm":         "SHA384",
			"status":                      "CREATED",
		},
	}

	tests := []struct {
		name    string
		state   *terraform.InstanceState
		config  map[string]any
		wantErr string
	}{
		{
			name:  "switch sectigo to lets encrypt drops provider specific attributes",
			state: sectigoState,
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
			},
		},
		{
			name:  "switch sectigo to lets encrypt keeps stale signature algorithm",
			state: sectigoState,
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
				"signature_algorithm":       "SHA384",
			},
			wantErr: "signature_algorithm is accepted",
		},
		{
			name: "valid lets encrypt",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "ECDSA256",
				"subject_alternative_names": []any{"www.example.com"},
			},
		},
		{
			name: "valid sectigo",
			config: map[string]any{
				"certificate_provider":        "SECTIGO",
				"algorithm":                   "RSA4096",
				"subject_alternative_names":   []any{"www.example.com"},
				"ssl_provider_credentials_id": 7,
				"renewal_interval":            30,
				"signature_algorithm":         "SHA384",
			},
		},
		{
			name: "lets encrypt rejects RSA4096",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA4096",
				"subject_alternative_names": []any{"www.example.com"},
			},
			wantErr: "LETS_ENCRYPT accepts the algorithms",
		},
		{
			name: "lets encrypt rejects renewal interval",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
				"renewal_interval":          10,
			},
			wantErr: "renewal_interval is accepted",
		},
		{
			name: "lets encrypt rejects signature algorithm",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
				"signature_algorithm":       "SHA256",
			},
			wantErr: "signature_algorithm is accepted",
		},
		{
			name: "sectigo needs credentials",
			config: map[string]any{
				"certificate_provider":      "SECTIGO",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"www.example.com"},
			},
			wantErr: "ssl_provider_credentials_id is required",
		},
		{
			name: "SHA512 with ECDSA",
			config: map[string]any{
				"certificate_provider":        "DTRUST",
				"algorithm":                   "ECDSA384",
				"subject_alternative_names":   []any{"www.example.com"},
				"ssl_provider_credentials_id": 7,
				"signature_algorithm":         "SHA512",
			},
			wantErr: "SHA512 cannot be combined",
		},
		{
			name: "lets encrypt rejects credentials",
			config: map[string]any{
				"certificate_provider":        "LETS_ENCRYPT",
				"algorithm":                   "RSA2048",
				"subject_alternative_names":   []any{"www.example.com"},
				"ssl_provider_credentials_id": 7,
			},
			wantErr: "ssl_provider_credentials_id is ignored",
		},
		{
			name: "redundant subject alternative name",
			config: map[string]any{
				"certificate_provider":      "LETS_ENCRYPT",
				"algorithm":                 "RSA2048",
				"subject_alternative_names": []any{"*.example.com", "www.example.com"},
			},
			wantErr: "would be dropped by the API",
		},
	}

	r := resourceMyrasecSSLCertificateRequest()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := r.Diff(context.Background(), tt.state, terraform.NewResourceConfigRaw(tt.config), nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestSSLCertificateRequestStateConverges plans a request with non-canonical names, applies the
// diff, refreshes the state from the canonical API answer and expects the next plan to be empty.
func TestSSLCertificateRequestStateConverges(t *testing.T) {
	r := resourceMyrasecSSLCertificateRequest()
	ctx := context.Background()

	config := terraform.NewResourceConfigRaw(map[string]any{
		"certificate_provider":      "LETS_ENCRYPT",
		"algorithm":                 "RSA2048",
		"subject_alternative_names": []any{"WWW.Example.com.", "*.Example.org"},
		"subdomains":                []any{"WWW.Example.com."},
		"configuration_name":        "2023-mozilla-modern",
	})

	diff, err := r.Diff(ctx, nil, config, nil)
	if err != nil {
		t.Fatalf("initial plan failed: %v", err)
	}

	// MergeDiff leaves the unknown placeholder in computed attributes, the apply below
	// replaces them with the API answer like a real apply does.
	var empty *terraform.InstanceState
	applied := empty.MergeDiff(diff)
	applied.ID = "1"
	for k, v := range applied.Attributes {
		if v == unknownVariableValue {
			delete(applied.Attributes, k)
		}
	}

	d := r.Data(applied)
	setSSLCertificateRequestData(d, &myrasec.SSLCertificateRequest{
		ID:        1,
		Provider:  "LETS_ENCRYPT",
		Algorithm: "RSA2048",
		Status:    "OPEN",
		SubjectAlternativeNames: []myrasec.SSLCertificateRequestSAN{
			{ID: 10, Name: "www.example.com"},
			{ID: 11, Name: "*.example.org"},
		},
		Assignments: []myrasec.SSLCertificateRequestAssignment{
			{ID: 20, SubDomainName: "www.example.com"},
		},
	})
	refreshed := d.State()

	if got := refreshed.Attributes["configuration_name"]; got != "2023-mozilla-modern" {
		t.Errorf("configuration_name = %q after refresh, want the configured value to survive", got)
	}

	diff, err = r.Diff(ctx, refreshed, config, nil)
	if err != nil {
		t.Fatalf("second plan failed: %v", err)
	}
	if diff != nil && !diff.Empty() {
		t.Errorf("expected an empty plan after refresh, got changes: %v", diff.Attributes)
	}

	// Removing configuration_name must not plan a change either, the API keeps the profile.
	withoutProfile := terraform.NewResourceConfigRaw(map[string]any{
		"certificate_provider":      "LETS_ENCRYPT",
		"algorithm":                 "RSA2048",
		"subject_alternative_names": []any{"www.example.com", "*.example.org"},
		"subdomains":                []any{"www.example.com"},
	})
	diff, err = r.Diff(ctx, refreshed, withoutProfile, nil)
	if err != nil {
		t.Fatalf("plan without configuration_name failed: %v", err)
	}
	if diff != nil && !diff.Empty() {
		t.Errorf("expected an empty plan without configuration_name, got changes: %v", diff.Attributes)
	}
}

// TestSSLCertificateRequestIncludeCrossSignedRoots pins the three properties the option needs:
// it defaults to off, the API answer round-trips into the state without a permanent diff (for a
// provider without such chains too, the API stores the value for every provider) and toggling it
// plans an in-place update, never a replacement: a replacement would re-issue a paid certificate.
func TestSSLCertificateRequestIncludeCrossSignedRoots(t *testing.T) {
	r := resourceMyrasecSSLCertificateRequest()
	ctx := context.Background()

	if def := r.Schema["include_cross_signed_roots"].Default; def != false {
		t.Errorf("include_cross_signed_roots default = %v, want false: an existing config must keep today's chain", def)
	}
	if r.Schema["include_cross_signed_roots"].ForceNew {
		t.Error("include_cross_signed_roots must not be ForceNew, a change would replace the request and re-issue the certificate")
	}

	for _, provider := range []string{"SECTIGO", "DTRUST"} {
		t.Run(provider, func(t *testing.T) {
			raw := map[string]any{
				"certificate_provider":        provider,
				"algorithm":                   "ECDSA256",
				"subject_alternative_names":   []any{"www.example.com"},
				"ssl_provider_credentials_id": 42,
				"include_cross_signed_roots":  true,
			}

			d := r.TestResourceData()
			d.SetId("1")
			setSSLCertificateRequestData(d, &myrasec.SSLCertificateRequest{
				ID:                       1,
				Provider:                 provider,
				Algorithm:                "ECDSA256",
				Status:                   "CREATED",
				SSLProviderCredentialsID: 42,
				IncludeCrossSignedRoots:  true,
				SubjectAlternativeNames:  []myrasec.SSLCertificateRequestSAN{{ID: 10, Name: "www.example.com"}},
			})
			refreshed := d.State()

			if got := refreshed.Attributes["include_cross_signed_roots"]; got != "true" {
				t.Fatalf("include_cross_signed_roots = %q after refresh, want true", got)
			}

			diff, err := r.Diff(ctx, refreshed, terraform.NewResourceConfigRaw(raw), nil)
			if err != nil {
				t.Fatalf("plan failed: %v", err)
			}
			if diff != nil && !diff.Empty() {
				t.Errorf("expected an empty plan after refresh, got changes: %v", diff.Attributes)
			}

			raw["include_cross_signed_roots"] = false
			diff, err = r.Diff(ctx, refreshed, terraform.NewResourceConfigRaw(raw), nil)
			if err != nil {
				t.Fatalf("plan with the option switched off failed: %v", err)
			}
			if diff == nil || diff.Attributes["include_cross_signed_roots"] == nil {
				t.Fatalf("expected a planned change of include_cross_signed_roots, got %v", diff)
			}
			if diff.RequiresNew() {
				t.Error("switching include_cross_signed_roots must update in place, the plan wants a replacement")
			}
		})
	}
}

// sslCertificateRequestTestAPI emulates the read and update calls of one stored request,
// including the optimistic locking of the API: an update is rejected unless the request and
// every subject alternative name and assignment sent with an ID carry the stored modified
// timestamp. Like the API it compares the formatted timestamps, so the same instant with
// another UTC offset is a mismatch.
type sslCertificateRequestTestAPI struct {
	mu      sync.Mutex
	request myrasec.SSLCertificateRequest
	updates []myrasec.SSLCertificateRequest
}

func (a *sslCertificateRequestTestAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	if r.URL.Path != "/ssl/requests/"+strconv.Itoa(a.request.ID) || (r.Method != http.MethodGet && r.Method != http.MethodPut) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.Method == http.MethodPut {
		var update myrasec.SSLCertificateRequest
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		a.updates = append(a.updates, update)

		if !a.unchanged(&update) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": true, "violationList": [{"message": "The record has been edited in the meantime."}]}`))
			return
		}

		a.request.IncludeCrossSignedRoots = update.IncludeCrossSignedRoots
		a.request.Modified = &types.DateTime{Time: a.request.Modified.Add(time.Minute)}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []*myrasec.SSLCertificateRequest{&a.request}})
}

// unchanged reports whether the update carries the modified timestamps the entries are stored
// with. An entry without ID is a new one, an ID that is not stored is rejected.
func (a *sslCertificateRequestTestAPI) unchanged(update *myrasec.SSLCertificateRequest) bool {
	same := func(sent, stored *types.DateTime) bool {
		return sent != nil && sent.Format(time.RFC3339) == stored.Format(time.RFC3339)
	}

	if !same(update.Modified, a.request.Modified) {
		return false
	}

	sans := make(map[int]*types.DateTime)
	for _, stored := range a.request.SubjectAlternativeNames {
		sans[stored.ID] = stored.Modified
	}
	for _, san := range update.SubjectAlternativeNames {
		if san.ID == 0 {
			continue
		}
		if stored, ok := sans[san.ID]; !ok || !same(san.Modified, stored) {
			return false
		}
	}

	assignments := make(map[int]*types.DateTime)
	for _, stored := range a.request.Assignments {
		assignments[stored.ID] = stored.Modified
	}
	for _, assignment := range update.Assignments {
		if assignment.ID == 0 {
			continue
		}
		if stored, ok := assignments[assignment.ID]; !ok || !same(assignment.Modified, stored) {
			return false
		}
	}

	return true
}

// TestSSLCertificateRequestUpdate switches include_cross_signed_roots on an existing request
// through the client the provider builds. The update has to reach the API although it follows a
// read of the same URL, the API has to accept it (optimistic locking of the stored names and
// assignments) and the refresh after the update must return the updated request.
func TestSSLCertificateRequestUpdate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cacheTTL int
	}{
		{name: "cache disabled", cacheTTL: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := time.Date(2026, 9, 1, 10, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
			date := func(offset time.Duration) *types.DateTime {
				return &types.DateTime{Time: stored.Add(offset)}
			}

			api := &sslCertificateRequestTestAPI{request: myrasec.SSLCertificateRequest{
				ID:        1,
				Created:   date(0),
				Modified:  date(3 * time.Hour),
				Provider:  "LETS_ENCRYPT",
				Algorithm: "RSA2048",
				Status:    "CREATED",
				SubjectAlternativeNames: []myrasec.SSLCertificateRequestSAN{
					{ID: 10, Name: "www.example.com", Created: date(0), Modified: date(time.Hour)},
				},
				Assignments: []myrasec.SSLCertificateRequestAssignment{
					{ID: 20, SubDomainName: "www.example.com", Created: date(0), Modified: date(2 * time.Hour)},
				},
			}}
			server := httptest.NewServer(api)
			t.Cleanup(server.Close)

			client, err := Config{
				APIToken:    "token",
				Language:    "en",
				APIBaseURL:  server.URL + "/%s",
				APICacheTTL: tc.cacheTTL,
			}.Client()
			if err != nil {
				t.Fatalf("building the API client failed: %v", err)
			}

			r := resourceMyrasecSSLCertificateRequest()
			ctx := context.Background()

			state, diags := r.RefreshWithoutUpgrade(ctx, &terraform.InstanceState{ID: "1"}, client)
			if diags.HasError() {
				t.Fatalf("refresh failed: %v", diags)
			}

			config := terraform.NewResourceConfigRaw(map[string]any{
				"certificate_provider":       "LETS_ENCRYPT",
				"algorithm":                  "RSA2048",
				"subject_alternative_names":  []any{"www.example.com"},
				"subdomains":                 []any{"www.example.com"},
				"include_cross_signed_roots": true,
			})

			diff, err := r.Diff(ctx, state, config, client)
			if err != nil {
				t.Fatalf("plan failed: %v", err)
			}
			if diff == nil || diff.Attributes["include_cross_signed_roots"] == nil {
				t.Fatalf("expected a planned change of include_cross_signed_roots, got %v", diff)
			}

			state, diags = r.Apply(ctx, state, diff, client)
			if diags.HasError() {
				t.Fatalf("apply failed: %v", diags)
			}

			if len(api.updates) != 1 {
				t.Fatalf("the API received %d updates, want 1", len(api.updates))
			}
			update := api.updates[0]
			if len(update.SubjectAlternativeNames) != 1 || update.SubjectAlternativeNames[0].ID != 10 {
				t.Errorf("SubjectAlternativeNames = %+v, want the stored entry 10 to be kept", update.SubjectAlternativeNames)
			}
			if len(update.Assignments) != 1 || update.Assignments[0].ID != 20 {
				t.Errorf("Assignments = %+v, want the stored entry 20 to be kept", update.Assignments)
			}
			if !api.request.IncludeCrossSignedRoots {
				t.Error("the API still stores include_cross_signed_roots = false after the apply")
			}
			if got := state.Attributes["include_cross_signed_roots"]; got != "true" {
				t.Errorf("include_cross_signed_roots = %q after the apply, want true", got)
			}

			state, diags = r.RefreshWithoutUpgrade(ctx, state, client)
			if diags.HasError() {
				t.Fatalf("refresh after the apply failed: %v", diags)
			}
			if got, want := state.Attributes["modified"], formatDateTime(api.request.Modified); got != want {
				t.Errorf("modified = %q after the refresh, want %q", got, want)
			}

			diff, err = r.Diff(ctx, state, config, client)
			if err != nil {
				t.Fatalf("plan after the apply failed: %v", err)
			}
			if diff != nil && !diff.Empty() {
				t.Errorf("expected an empty plan after the apply, got changes: %v", diff.Attributes)
			}
		})
	}
}

func TestSSLCertificateRequestSchemaValidation(t *testing.T) {
	r := resourceMyrasecSSLCertificateRequest()

	for _, valid := range []string{"LETS_ENCRYPT", "SECTIGO", "DTRUST"} {
		if _, errs := r.Schema["certificate_provider"].ValidateFunc(valid, "certificate_provider"); len(errs) > 0 {
			t.Errorf("certificate_provider %q should be valid: %v", valid, errs)
		}
	}
	if _, errs := r.Schema["certificate_provider"].ValidateFunc("lets_encrypt", "certificate_provider"); len(errs) == 0 {
		t.Error("certificate_provider should be case sensitive")
	}

	for _, valid := range []string{"RSA2048", "RSA4096", "RSA8192", "ECDSA256", "ECDSA384"} {
		if _, errs := r.Schema["algorithm"].ValidateFunc(valid, "algorithm"); len(errs) > 0 {
			t.Errorf("algorithm %q should be valid: %v", valid, errs)
		}
	}
	if _, errs := r.Schema["algorithm"].ValidateFunc("RSA1024", "algorithm"); len(errs) == 0 {
		t.Error("algorithm RSA1024 should be invalid")
	}
	if !r.Schema["algorithm"].ForceNew {
		t.Error("algorithm is immutable and has to be ForceNew")
	}

	if _, errs := r.Schema["renewal_interval"].ValidateFunc(-1, "renewal_interval"); len(errs) == 0 {
		t.Error("renewal_interval -1 should be invalid")
	}
}
