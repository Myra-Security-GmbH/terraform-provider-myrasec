package myrasec

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func tagJSON(id int) map[string]any {
	return map[string]any{
		"id": id, "name": "tag-" + strconv.Itoa(id), "type": "CONFIG", "sort": 1, "global": false,
		"created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z", "assignments": []any{},
	}
}

// TestListTagsPageIgnored covers a list endpoint that returns the same full page for every
// page number: listTags must return the page once and stop instead of looping forever.
// The SDK rate limiter allows five requests per second, so the test stays at two calls.
func TestListTagsPageIgnored(t *testing.T) {
	listCalls := 0
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/tags" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		listCalls++
		tags := make([]any, 0, listPageSize)
		for id := 1; id <= listPageSize; id++ {
			tags = append(tags, tagJSON(id))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": tags})
	}))

	tags, diags := listTags(client, map[string]string{})
	if diags.HasError() {
		t.Fatal(diags)
	}
	if listCalls != 2 {
		t.Errorf("list endpoint was called %d times, want 2", listCalls)
	}
	if len(tags) != listPageSize {
		t.Errorf("got %d tags, want %d", len(tags), listPageSize)
	}
}

// TestTagsDataSourceRead covers the read of a short page: one list call, one detail call per
// tag and the tags in the state.
func TestTagsDataSourceRead(t *testing.T) {
	listCalls := 0
	detailCalls := 0
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/tags" {
			listCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{tagJSON(1), tagJSON(2)}})
			return
		}
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/tags/"))
		if err != nil {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		detailCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{tagJSON(id)}})
	}))

	d := dataSourceMyrasecTags().TestResourceData()
	if diags := dataSourceMyrasecTagsRead(context.Background(), d, client); diags.HasError() {
		t.Fatal(diags)
	}
	if listCalls != 1 || detailCalls != 2 {
		t.Errorf("got %d list and %d detail calls, want 1 and 2", listCalls, detailCalls)
	}
	tags := d.Get("tags").([]any)
	if len(tags) != 2 || tags[1].(map[string]any)["name"] != "tag-2" {
		t.Errorf("unexpected tags in state: %v", tags)
	}
}

func TestTagsDataSourceTagErrorSurfaces(t *testing.T) {
	client := domainTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/tags" {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": false, "data": []any{tagJSON(1)}})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":true,"violationList":[{"message":"read denied"}]}`))
	}))

	d := dataSourceMyrasecTags().TestResourceData()
	diags := dataSourceMyrasecTagsRead(context.Background(), d, client)
	if !diags.HasError() || !strings.Contains(diags[0].Detail, "read denied") {
		t.Fatalf("tag lookup error was lost: %v", diags)
	}
}
