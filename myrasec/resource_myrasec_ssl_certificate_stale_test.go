package myrasec

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
	staleCertPath      = "/domain/1/certificates/7"
	staleCertReadPath  = "/domain/1/ssl/certificates/7"
	staleMessage       = "The record has been edited in the meantime."
	plannedModified    = "2026-10-01T07:00:00Z"
	serverSideModified = "2026-10-01T07:49:44Z"
	stateFingerprint   = "AA:BB:CC"
	stateConfiguration = "2023-mozilla-intermediate"
)

// serverCert is what a read of certificate 7 returns.
type serverCert struct {
	id            int
	modified      string
	fingerprint   string
	configuration string
	subdomains    []string
}

// deletedRecordServer is the state a deleted DNS record leaves on the server: the deleted DNS record took
// "old.example.com" off the certificate and moved its modified timestamp.
func deletedRecordServer() serverCert {
	return serverCert{id: 7, modified: serverSideModified, fingerprint: stateFingerprint,
		configuration: stateConfiguration, subdomains: []string{"www.example.com"}}
}

// deletedRecordGuard is the plan of that apply: the state has both subdomains, the plan drops
// "old.example.com".
func deletedRecordGuard() sslStaleRetryGuard {
	return sslStaleRetryGuard{
		stateSubdomains:        []string{"www.example.com", "old.example.com"},
		plannedSubdomains:      []string{"www.example.com"},
		stateFingerprint:       stateFingerprint,
		stateConfigurationName: stateConfiguration,
	}
}

// staleCertServer answers the update and the read of certificate 7 on domain 1. putStatus lists
// the status of each PUT in order (200 = success). It records the modified timestamp and the
// subdomains every PUT carried and counts the reads.
type staleCertServer struct {
	t             *testing.T
	putStatus     []int
	getStatus     int
	read          serverCert
	putModified   []string
	putSubdomains [][]string
	gets          int
}

func (s *staleCertServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPut && r.URL.Path == staleCertPath:
		var body struct {
			Modified   string   `json:"modified"`
			Subdomains []string `json:"subdomains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.t.Errorf("decode request: %v", err)
		}
		s.putModified = append(s.putModified, body.Modified)
		s.putSubdomains = append(s.putSubdomains, body.Subdomains)
		n := len(s.putModified)
		if n > len(s.putStatus) {
			s.t.Errorf("unexpected PUT #%d", n)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if status := s.putStatus[n-1]; status != http.StatusOK {
			msg := staleMessage
			if status != http.StatusBadRequest {
				msg = "update denied"
			}
			accessError(w, status, msg)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{
			map[string]any{"id": 7, "created": plannedModified, "modified": "2026-10-01T08:00:00Z",
				"fingerprint": stateFingerprint, "sslConfigurationName": stateConfiguration, "subdomains": body.Subdomains},
		}})
	case r.Method == http.MethodGet && r.URL.Path == staleCertReadPath:
		s.gets++
		if s.getStatus != http.StatusOK {
			accessError(w, s.getStatus, "read denied")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{
			map[string]any{"id": s.read.id, "created": plannedModified, "modified": s.read.modified,
				"fingerprint": s.read.fingerprint, "sslConfigurationName": s.read.configuration, "subdomains": s.read.subdomains},
		}})
	default:
		s.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func plannedSSLCertificate(t *testing.T, subdomains []string) *myrasec.SSLCertificate {
	t.Helper()
	modified, err := time.Parse(time.RFC3339, plannedModified)
	if err != nil {
		t.Fatal(err)
	}
	return &myrasec.SSLCertificate{
		Certificate:          &myrasec.Certificate{ID: 7, Modified: &types.DateTime{Time: modified}, Fingerprint: stateFingerprint},
		Subdomains:           subdomains,
		SslConfigurationName: stateConfiguration,
	}
}

// TestSSLCertificateUpdateRetriesStaleModified pins the stale-modified retry: deleting a DNS record in the same
// apply removes the subdomain from the certificate on the server and moves its modified
// timestamp, so the planned update is refused as "edited in the meantime". The update is sent
// once more with the current timestamp ONLY in that case. Every other refusal, in particular any
// server-side change the plan did not make itself, is reported unchanged and never overwritten.
func TestSSLCertificateUpdateRetriesStaleModified(t *testing.T) {
	type tcase struct {
		name      string
		putStatus []int
		getStatus int
		read      func(serverCert) serverCert
		guard     func(sslStaleRetryGuard) sslStaleRetryGuard
		// planned are the subdomains the plan sends (default: [www.example.com]); they are
		// both the guard's planned subdomains and the body of every PUT.
		planned  []string
		wantErr  string
		wantPuts []string
		wantGets int
	}
	same := func(c serverCert) serverCert { return c }
	sameGuard := func(g sslStaleRetryGuard) sslStaleRetryGuard { return g }
	noRetry := []string{plannedModified}

	cases := []tcase{
		{
			name:      "record deleted: server dropped the planned-removed subdomain, one retry with the current timestamp",
			putStatus: []int{http.StatusBadRequest, http.StatusOK}, getStatus: http.StatusOK,
			wantPuts: []string{plannedModified, serverSideModified}, wantGets: 1,
		},
		{
			name:      "record deleted, the server answering upper case and a trailing dot",
			putStatus: []int{http.StatusBadRequest, http.StatusOK}, getStatus: http.StatusOK,
			read:     func(c serverCert) serverCert { c.subdomains = []string{"WWW.example.com."}; return c },
			wantPuts: []string{plannedModified, serverSideModified}, wantGets: 1,
		},
		{
			name:      "two records deleted: two subdomains dropped by two deleted DNS records",
			putStatus: []int{http.StatusBadRequest, http.StatusOK}, getStatus: http.StatusOK,
			read: func(c serverCert) serverCert { c.subdomains = []string{"www.example.com"}; return c },
			guard: func(g sslStaleRetryGuard) sslStaleRetryGuard {
				g.stateSubdomains = []string{"www.example.com", "a.example.com", "b.example.com"}
				return g
			},
			wantPuts: []string{plannedModified, serverSideModified}, wantGets: 1,
		},
		{
			name:      "record created with auto certificates: server assigned the new subdomain the plan adds too",
			putStatus: []int{http.StatusBadRequest, http.StatusOK}, getStatus: http.StatusOK,
			read: func(c serverCert) serverCert {
				c.subdomains = []string{"www.example.com", "new.example.com"}
				return c
			},
			guard: func(g sslStaleRetryGuard) sslStaleRetryGuard {
				g.stateSubdomains = []string{"www.example.com"}
				return g
			},
			planned:  []string{"www.example.com", "new.example.com"},
			wantPuts: []string{plannedModified, serverSideModified}, wantGets: 1,
		},
		{
			name:      "record renamed: server dropped the old name, the plan swaps it for the new one",
			putStatus: []int{http.StatusBadRequest, http.StatusOK}, getStatus: http.StatusOK,
			planned:  []string{"www.example.com", "renamed.example.com"},
			wantPuts: []string{plannedModified, serverSideModified}, wantGets: 1,
		},
		{
			name:      "server assigned a subdomain the plan adds, but ALSO one the plan does not assign",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read: func(c serverCert) serverCert {
				c.subdomains = []string{"www.example.com", "new.example.com", "foreign.example.com"}
				return c
			},
			guard: func(g sslStaleRetryGuard) sslStaleRetryGuard {
				g.stateSubdomains = []string{"www.example.com"}
				return g
			},
			planned: []string{"www.example.com", "new.example.com"},
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "server assigned a subdomain the plan adds, but dropped one the plan keeps",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read: func(c serverCert) serverCert {
				c.subdomains = []string{"new.example.com"}
				return c
			},
			guard: func(g sslStaleRetryGuard) sslStaleRetryGuard {
				g.stateSubdomains = []string{"www.example.com"}
				return g
			},
			planned: []string{"www.example.com", "new.example.com"},
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "retry refused again: reported, never a third attempt",
			putStatus: []int{http.StatusBadRequest, http.StatusBadRequest}, getStatus: http.StatusOK,
			wantErr: staleMessage, wantPuts: []string{plannedModified, serverSideModified}, wantGets: 1,
		},
		{
			name:      "concurrent change: someone ADDED a subdomain on the server",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read: func(c serverCert) serverCert {
				c.subdomains = []string{"www.example.com", "new.example.com"}
				return c
			},
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "concurrent change: server dropped a subdomain the plan KEEPS",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read:    func(c serverCert) serverCert { c.subdomains = []string{"old.example.com"}; return c },
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "concurrent change: subdomains untouched, something else moved modified",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read: func(c serverCert) serverCert {
				c.subdomains = []string{"www.example.com", "old.example.com"}
				return c
			},
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "concurrent change: TLS configuration changed on the server",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read:    func(c serverCert) serverCert { c.configuration = "2023-mozilla-modern"; return c },
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "concurrent change: certificate replaced (fingerprint changed)",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read:    func(c serverCert) serverCert { c.fingerprint = "DD:EE:FF"; return c },
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "state without a fingerprint: cannot prove it is the same certificate",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read: func(c serverCert) serverCert { c.fingerprint = ""; return c },
			guard: func(g sslStaleRetryGuard) sslStaleRetryGuard {
				g.stateFingerprint = ""
				return g
			},
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "read answers another certificate ID",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read:    func(c serverCert) serverCert { c.id = 8; return c },
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "400 with unchanged modified is a genuine validation error",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusOK,
			read:    func(c serverCert) serverCert { c.modified = plannedModified; return c },
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "re-read fails: the original refusal is reported",
			putStatus: []int{http.StatusBadRequest}, getStatus: http.StatusForbidden,
			wantErr: staleMessage, wantPuts: noRetry, wantGets: 1,
		},
		{
			name:      "non-400 refusal: no re-read, no retry",
			putStatus: []int{http.StatusForbidden},
			wantErr:   "update denied", wantPuts: noRetry, wantGets: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.read == nil {
				tc.read = same
			}
			if tc.guard == nil {
				tc.guard = sameGuard
			}
			if tc.planned == nil {
				tc.planned = []string{"www.example.com"}
			}
			srv := &staleCertServer{t: t, putStatus: tc.putStatus, getStatus: tc.getStatus, read: tc.read(deletedRecordServer())}
			client := domainTestClient(t, srv)
			planned := plannedSSLCertificate(t, tc.planned)
			guard := tc.guard(deletedRecordGuard())
			guard.plannedSubdomains = tc.planned

			got, err := updateSSLCertificateRetryingStale(client, planned, 1, guard)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got == nil || got.ID != 7 {
					t.Fatalf("updated certificate not returned: %+v", got)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}

			if !slices.Equal(srv.putModified, tc.wantPuts) {
				t.Errorf("PUT modified timestamps = %v, want %v", srv.putModified, tc.wantPuts)
			}
			for i, sub := range srv.putSubdomains {
				if !slices.Equal(sub, tc.planned) {
					t.Errorf("PUT #%d sent subdomains %v, want the planned %v", i+1, sub, tc.planned)
				}
			}
			if srv.gets != tc.wantGets {
				t.Errorf("re-reads = %d, want %d", srv.gets, tc.wantGets)
			}
			if planned.Modified.Format(time.RFC3339) != plannedModified {
				t.Errorf("the caller's certificate was mutated: modified = %s", planned.Modified.Format(time.RFC3339))
			}
		})
	}
}

// TestSSLStaleRetryGuardFromState checks that the guard is built from the PRIOR state of an
// update (subdomains, fingerprint, configuration) and the PLANNED subdomains, on a real
// plan/apply diff of the resource.
func TestSSLStaleRetryGuardFromState(t *testing.T) {
	r := resourceMyrasecSSLCertificate()
	state := &terraform.InstanceState{
		ID: "7",
		Attributes: map[string]string{
			"id":                 "7",
			"certificate_id":     "7",
			"domain_name":        "example.com",
			"domain_id":          "1",
			"fingerprint":        stateFingerprint,
			"configuration_name": stateConfiguration,
			"modified":           plannedModified,
			"created":            plannedModified,
			"subdomains.#":       "2",
		},
	}
	// TypeSet of strings: the element keys are the set hashes.
	for _, s := range []string{"www.example.com", "old.example.com"} {
		state.Attributes["subdomains."+schemaHashString(s)] = s
	}
	diff := &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
		"subdomains.#": {Old: "2", New: "1"},
		"subdomains." + schemaHashString("old.example.com"): {Old: "old.example.com", New: "", NewRemoved: true},
		"subdomains." + schemaHashString("www.example.com"): {Old: "www.example.com", New: "www.example.com"},
	}}

	d, err := schemaMapData(r, state, diff)
	if err != nil {
		t.Fatal(err)
	}

	g := sslStaleRetryGuardFromState(d)
	slices.Sort(g.stateSubdomains)
	if !slices.Equal(g.stateSubdomains, []string{"old.example.com", "www.example.com"}) {
		t.Errorf("stateSubdomains = %v", g.stateSubdomains)
	}
	if !slices.Equal(g.plannedSubdomains, []string{"www.example.com"}) {
		t.Errorf("plannedSubdomains = %v", g.plannedSubdomains)
	}
	if g.stateFingerprint != stateFingerprint || g.stateConfigurationName != stateConfiguration {
		t.Errorf("fingerprint/configuration = %q/%q", g.stateFingerprint, g.stateConfigurationName)
	}

	if !serverChangeMatchesPlannedSubdomains(&myrasec.SSLCertificate{
		Certificate:          &myrasec.Certificate{ID: 7, Fingerprint: stateFingerprint},
		SslConfigurationName: stateConfiguration,
		Subdomains:           []string{"www.example.com"},
	}, 7, g) {
		t.Error("the deleted-record server state is not accepted with the guard of a real diff")
	}
}

func schemaHashString(s string) string {
	return strconv.Itoa(schema.HashString(s))
}

func schemaMapData(r *schema.Resource, state *terraform.InstanceState, diff *terraform.InstanceDiff) (*schema.ResourceData, error) {
	return schema.InternalMap(r.SchemaMap()).Data(state, diff)
}
