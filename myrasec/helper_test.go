package myrasec

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// unknownVariableValue is the placeholder the SDK stores for values that are unknown until apply
const unknownVariableValue = "74D93920-ED26-11E3-AC10-0800200C9A66"

func pageOfInts(first, count int) []int {
	rows := make([]int, count)
	for i := range rows {
		rows[i] = first + i
	}
	return rows
}

// TestListPagesStopsWhenPageIsIgnored covers an endpoint that returns the same full page for
// every page number: the walk must end instead of looping forever.
func TestListPagesStopsWhenPageIsIgnored(t *testing.T) {
	calls := 0
	got, err := listPages(nil, func(row int) int { return row }, func(params map[string]string) ([]int, error) {
		calls++
		if params["pageSize"] != strconv.Itoa(listPageSize) || params["page"] != strconv.Itoa(calls) {
			t.Errorf("call %d: unexpected params %v", calls, params)
		}
		return pageOfInts(1, listPageSize), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("fetch was called %d times, want 2", calls)
	}
	if len(got) != listPageSize {
		t.Errorf("got %d rows, want %d", len(got), listPageSize)
	}
}

// TestListPagesStopsWhenPageIsIgnoredWithoutIDs covers the same endpoint for rows without
// an id: the walk must still end.
func TestListPagesStopsWhenPageIsIgnoredWithoutIDs(t *testing.T) {
	calls := 0
	got, err := listPages(nil, func(int) int { return 0 }, func(map[string]string) ([]int, error) {
		calls++
		return pageOfInts(1, listPageSize), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("fetch was called %d times, want 2", calls)
	}
	if len(got) != listPageSize {
		t.Errorf("got %d rows, want %d", len(got), listPageSize)
	}
}

func TestListPagesCollectsAllPages(t *testing.T) {
	pages := [][]int{pageOfInts(1, listPageSize), pageOfInts(listPageSize+1, 10)}
	calls := 0
	got, err := listPages(map[string]string{"search": "x"}, func(row int) int { return row }, func(params map[string]string) ([]int, error) {
		calls++
		if params["search"] != "x" {
			t.Errorf("call %d: search parameter was lost: %v", calls, params)
		}
		if calls > len(pages) {
			return nil, errors.New("page beyond the last one requested")
		}
		return pages[calls-1], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(got) != listPageSize+10 || got[len(got)-1] != listPageSize+10 {
		t.Errorf("calls=%d rows=%d last=%d", calls, len(got), got[len(got)-1])
	}
}

func TestListPagesPropagatesError(t *testing.T) {
	want := errors.New("listing failed")
	calls := 0
	_, err := listPages(nil, func(row int) int { return row }, func(params map[string]string) ([]int, error) {
		calls++
		if calls == 1 {
			return pageOfInts(1, listPageSize), nil
		}
		return nil, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestFindInPages(t *testing.T) {
	t.Run("stops at the match", func(t *testing.T) {
		calls := 0
		found, err := findInPages(nil, func(row int) int { return row }, func(params map[string]string) ([]int, error) {
			calls++
			return pageOfInts(1, listPageSize), nil
		}, func(row int) bool { return row == 5 })
		if err != nil {
			t.Fatal(err)
		}
		if found == nil || *found != 5 || calls != 1 {
			t.Errorf("found=%v calls=%d", found, calls)
		}
	})

	t.Run("nil without match", func(t *testing.T) {
		found, err := findInPages(nil, func(row int) int { return row }, func(params map[string]string) ([]int, error) {
			return pageOfInts(1, 3), nil
		}, func(row int) bool { return row == 5 })
		if err != nil {
			t.Fatal(err)
		}
		if found != nil {
			t.Errorf("found %v, want nil", *found)
		}
	})

	t.Run("rows without id are not deduplicated", func(t *testing.T) {
		calls := 0
		_, err := findInPages(nil, func(row int) int { return 0 }, func(params map[string]string) ([]int, error) {
			calls++
			if calls == 1 {
				return pageOfInts(0, listPageSize), nil
			}
			return nil, nil
		}, func(row int) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		if calls != 2 {
			t.Errorf("fetch was called %d times, want 2", calls)
		}
	})
}

func TestSuppressEquivalentDateTime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		oldValue string
		newValue string
		want     bool
	}{
		{name: "same instant other offset", oldValue: "2026-12-31T23:00:00Z", newValue: "2027-01-01T00:00:00+01:00", want: true},
		{name: "same value", oldValue: "2026-12-31T23:00:00Z", newValue: "2026-12-31T23:00:00Z", want: true},
		{name: "fractional seconds", oldValue: "2026-12-31T23:00:00Z", newValue: "2026-12-31T23:00:00.000Z", want: true},
		{name: "other instant", oldValue: "2026-12-31T23:00:00Z", newValue: "2026-12-31T23:00:01Z"},
		{name: "unset old", oldValue: "", newValue: "2026-12-31T23:00:00Z"},
		{name: "unset new", oldValue: "2026-12-31T23:00:00Z", newValue: ""},
		{name: "both unset", oldValue: "", newValue: ""},
		{name: "invalid", oldValue: "yesterday", newValue: "2026-12-31T23:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := suppressEquivalentDateTime("expire_date", tc.oldValue, tc.newValue, nil); got != tc.want {
				t.Errorf("suppress(%q, %q) = %v, want %v", tc.oldValue, tc.newValue, got, tc.want)
			}
		})
	}
}

func TestFormatDateTime(t *testing.T) {
	if got := formatDateTime(nil); got != "" {
		t.Errorf("nil date formatted as %q", got)
	}
	date, err := types.ParseDate("2027-01-01T00:00:00+01:00")
	if err != nil {
		t.Fatal(err)
	}
	if got := formatDateTime(date); got != "2027-01-01T00:00:00+01:00" {
		t.Errorf("formatted as %q", got)
	}
}

func TestFinishImport(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{"name": {Type: schema.TypeString, Optional: true}}}

	t.Run("read error", func(t *testing.T) {
		d := r.TestResourceData()
		d.SetId("1")
		read := func(context.Context, *schema.ResourceData, any) diag.Diagnostics {
			return diag.Diagnostics{
				{Severity: diag.Warning, Summary: "ignored warning"},
				{Severity: diag.Error, Summary: "Error loading object", Detail: "read denied"},
			}
		}
		result, err := finishImport(context.Background(), d, nil, read)
		if err == nil || !strings.Contains(err.Error(), "read denied") || !strings.Contains(err.Error(), "Error loading object") {
			t.Fatalf("read error was lost: %v", err)
		}
		if result != nil {
			t.Errorf("result %v returned with the error", result)
		}
	})

	t.Run("object missing", func(t *testing.T) {
		d := r.TestResourceData()
		d.SetId("1")
		read := func(_ context.Context, d *schema.ResourceData, _ any) diag.Diagnostics {
			d.SetId("")
			return nil
		}
		if _, err := finishImport(context.Background(), d, nil, read); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("empty ID after the read was accepted: %v", err)
		}
	})

	t.Run("success keeps warnings out of the error", func(t *testing.T) {
		d := r.TestResourceData()
		d.SetId("1")
		read := func(_ context.Context, d *schema.ResourceData, _ any) diag.Diagnostics {
			if err := d.Set("name", "imported"); err != nil {
				t.Fatal(err)
			}
			return diag.Diagnostics{{Severity: diag.Warning, Summary: "verification pending"}}
		}
		result, err := finishImport(context.Background(), d, nil, read)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 1 || result[0].Id() != "1" || result[0].Get("name") != "imported" {
			t.Errorf("unexpected result %v", result)
		}
	})
}
