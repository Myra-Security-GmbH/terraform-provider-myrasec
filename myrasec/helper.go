package myrasec

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// findDomainByDomainName ...
func findDomainByDomainName(meta any, domainName string) (domain *myrasec.Domain, diags diag.Diagnostics) {

	client := meta.(*myrasec.API)
	domain, err := client.FetchDomain(domainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given domain name",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	return domain, diags
}

// findDomainIDByDomainName ...
func findDomainIDByDomainName(d *schema.ResourceData, meta any, domainName string) (domainID int, diags diag.Diagnostics) {

	stateDomainID, ok := d.GetOk("domain_id")

	if !ok {
		domain, diags := findDomainByDomainName(meta, domainName)
		if diags.HasError() {
			return 0, diags
		}
		domainID = domain.ID
	} else {
		domainID = stateDomainID.(int)
	}

	return domainID, diags
}

// findDomainID ...
func findDomainID(d *schema.ResourceData, meta any) (domainID int, diags diag.Diagnostics) {

	stateDomainID, ok := d.GetOk("domain_id")

	if !ok {
		name, ok := d.GetOk("subdomain_name")
		if !ok {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error parsing resource information",
				Detail:   formatError(fmt.Errorf("[subdomain_name] is not set")),
			})
			return 0, diags
		}

		subDomainName := name.(string)

		if myrasec.IsGeneralDomainName(subDomainName) && strings.HasPrefix(subDomainName, "ALL-") {
			var err error
			domainID, err = myrasec.ExtractDomainIdFromGeneralDomainName(subDomainName)
			if err == nil {
				return domainID, diags
			}
		}

		domain, diags := findDomainBySubdomainName(meta, subDomainName)
		if diags.HasError() || domain == nil {
			return 0, diags
		}
		domainID = domain.ID
	} else {
		domainID = stateDomainID.(int)
	}

	return domainID, diags
}

// findSubdomainNameAndDomainID ...
func findSubdomainNameAndDomainID(d *schema.ResourceData, meta any) (domainID int, subDomainName string, diags diag.Diagnostics) {

	name, ok := d.GetOk("subdomain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[subdomain_name] is not set")),
		})
		return 0, "", diags
	}

	subDomainName = name.(string)

	stateDomainID, ok := d.GetOk("domain_id")
	if ok {
		domainID = stateDomainID.(int)
		return domainID, subDomainName, diags
	}

	if myrasec.IsGeneralDomainName(subDomainName) && strings.HasPrefix(subDomainName, "ALL-") {
		var err error
		domainID, err = myrasec.ExtractDomainIdFromGeneralDomainName(subDomainName)
		if err == nil {
			return domainID, subDomainName, diags
		}
	}

	domain, diags := findDomainBySubdomainName(meta, subDomainName)
	if diags.HasError() || domain == nil {
		return 0, subDomainName, diags
	}
	domainID = domain.ID

	return domainID, subDomainName, diags
}

// findDomainBySubdomainName ...
func findDomainBySubdomainName(meta any, subDomainName string) (*myrasec.Domain, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	domain, err := client.FetchDomainForSubdomainName(subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(100 * time.Millisecond)

	return domain, diags
}

// lookupDiagnostics converts the error of a single object lookup into diagnostics. A missing
// object is a warning, the caller drops the resource from the state so the next apply
// recreates it. Every other error (authorization, network, server) is an error: the state is
// kept and the run fails instead of silently planning a recreation.
func lookupDiagnostics(what string, id int, err error) diag.Diagnostics {
	if isNotFoundError(err) {
		return diag.Diagnostics{{
			Severity: diag.Warning,
			Summary:  fmt.Sprintf("Unable to find %s", what),
			Detail:   fmt.Sprintf("Unable to find %s with ID = [%d]", what, id),
		}}
	}

	return diag.Diagnostics{{
		Severity: diag.Error,
		Summary:  fmt.Sprintf("Error loading %s", what),
		Detail:   formatError(err),
	}}
}

// finishImport runs the read function of an imported resource and turns its result into the
// outcome of the import: an error diagnostic fails the import and a read that cleared the ID
// means the object does not exist.
func finishImport(ctx context.Context, d *schema.ResourceData, meta any, read schema.ReadContextFunc) ([]*schema.ResourceData, error) {
	if diags := read(ctx, d, meta); diags.HasError() {
		return nil, diagnosticsError(diags)
	}

	if d.Id() == "" {
		return nil, errors.New("the imported resource does not exist")
	}

	return []*schema.ResourceData{d}, nil
}

// diagnosticsError joins the error diagnostics into a single error
func diagnosticsError(diags diag.Diagnostics) error {
	var errs []error
	for _, dg := range diags {
		if dg.Severity != diag.Error {
			continue
		}
		if dg.Detail == "" {
			errs = append(errs, errors.New(dg.Summary))
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %s", dg.Summary, dg.Detail))
	}

	return errors.Join(errs...)
}

// listPageSize is the number of rows requested per page from the list endpoints
const listPageSize = 250

// forEachPage walks the pages of a list endpoint and hands every row to visit until visit
// returns true. The walk ends with a short page, an empty page, a page that brings no new
// row or a page equal to the one before: an endpoint that ignores the page parameter returns
// the same rows for every page and must not loop forever. Rows are told apart by id, a row
// whose id is 0 counts as new, the comparison of whole pages covers rows without an id.
func forEachPage[T any](params map[string]string, id func(T) int, fetch func(map[string]string) ([]T, error), visit func(T) bool) error {
	if params == nil {
		params = map[string]string{}
	}
	params["pageSize"] = strconv.Itoa(listPageSize)

	seen := map[int]struct{}{}
	var previous []T
	for page := 1; ; page++ {
		params["page"] = strconv.Itoa(page)

		rows, err := fetch(params)
		if err != nil {
			return err
		}
		if page > 1 && reflect.DeepEqual(rows, previous) {
			return nil
		}
		previous = rows

		added := 0
		for _, row := range rows {
			if key := id(row); key > 0 {
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
			}
			added++

			if visit(row) {
				return nil
			}
		}

		if len(rows) < listPageSize || added == 0 {
			return nil
		}
	}
}

// listPages collects every row of a list endpoint, see forEachPage
func listPages[T any](params map[string]string, id func(T) int, fetch func(map[string]string) ([]T, error)) ([]T, error) {
	var rows []T

	err := forEachPage(params, id, fetch, func(row T) bool {
		rows = append(rows, row)
		return false
	})

	return rows, err
}

// findInPages returns the first row of a list endpoint that match accepts, nil when there is none
func findInPages[T any](params map[string]string, id func(T) int, fetch func(map[string]string) ([]T, error), match func(T) bool) (*T, error) {
	var found *T

	err := forEachPage(params, id, fetch, func(row T) bool {
		if !match(row) {
			return false
		}
		found = &row
		return true
	})

	return found, err
}

// suppressEquivalentDateTime is a DiffSuppressFunc for date attributes: the API reports a date
// in its own time zone offset, so a configured value naming the same instant in another offset
// (or with a different precision) is not a change.
func suppressEquivalentDateTime(_, oldValue, newValue string, _ *schema.ResourceData) bool {
	oldDate, err := types.ParseDate(oldValue)
	if err != nil || oldDate == nil {
		return false
	}

	newDate, err := types.ParseDate(newValue)
	if err != nil || newDate == nil {
		return false
	}

	return oldDate.Equal(newDate.Time)
}

// parseResourceServiceID splits the passed id (format like string:integer) to separate values
func parseResourceServiceID(id string) (string, int, error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", 0, fmt.Errorf("unexpected format of ID (%s), expected name:ID", id)
	}

	recordID, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("second part of ID is not an integer value (%s)", id)
	}

	return parts[0], recordID, nil
}

// StringInSlice checks if the haystack []string slice contains the passed needle string
func StringInSlice(needle string, haystack []string) bool {
	for _, a := range haystack {
		if a == needle {
			return true
		}
	}
	return false
}

// IntInSlice checks if the haystack []int slice contains the passed needle int
func IntInSlice(needle int, haystack []int) bool {
	for _, a := range haystack {
		if a == needle {
			return true
		}
	}
	return false
}

// formatError returns the error message with a timestamp appended to it
func formatError(err error) string {
	return fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339Nano), err.Error())
}

func createContentHash(content string) string {
	h := sha256.New()
	h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// isNotFoundError reports whether the passed error says that the requested object does not exist.
// The API answers a missing object with HTTP 404 or HTTP 403 carrying a
// "does-not-exist" violation (including localized entity messages). Violations of other status codes refer
// to referenced objects (e.g. a dangling credentials ID in a 400) and are not a not-found.
func isNotFoundError(err error) bool {
	var apiErr *myrasec.APIError
	if !errors.As(err, &apiErr) {
		return false
	}

	if apiErr.StatusCode == http.StatusNotFound {
		return true
	}

	if apiErr.StatusCode != http.StatusForbidden {
		return false
	}

	for _, v := range apiErr.Violations {
		if v == nil {
			continue
		}
		switch strings.TrimSpace(v.Message) {
		case "does-not-exist", "api.error.does-not-exist", "The entity does not exist.", "Die Entität existiert nicht.":
			return true
		}
	}

	return false
}

// formatDateTime formats the passed date as RFC3339 and returns an empty string for a nil date
func formatDateTime(dt *types.DateTime) string {
	if dt == nil {
		return ""
	}
	return dt.Format(time.RFC3339)
}

// expandStringSet converts the passed *schema.Set of strings to a []string slice.
// A value of another type is a schema error and panics like every other d.Get assertion.
func expandStringSet(v any) []string {
	set := v.(*schema.Set)

	result := make([]string, 0, set.Len())
	for _, item := range set.List() {
		result = append(result, item.(string))
	}
	return result
}

// normalizeDomainName lowercases the passed name and removes a trailing dot
func normalizeDomainName(name string) string {
	return strings.ToLower(myrasec.RemoveTrailingDot(name))
}

// hashDomainName is a schema.Set hash function for domain names. It hashes the normalized
// name, so that a non-canonical configuration value ("WWW.Example.com.") and the canonical
// value returned by the API land in the same set element and do not produce a permanent diff.
func hashDomainName(v any) int {
	return schema.HashString(normalizeDomainName(v.(string)))
}

// settingsBoolValue converts a boolean setting to the value the settings API expects.
// The API declares ip_lock as a string parameter and only maps the values "yes" and "no"
// to a boolean. A JSON boolean is coerced to "1" or "" there and stored verbatim: the
// platform treats such a value as "lock disabled" and the settings response returns it as
// a string, which does not fit the boolean attribute and leaves the state without a value.
// Every other boolean setting is sent as JSON boolean.
func settingsBoolValue(name string, value bool) any {
	if name != "ip_lock" {
		return value
	}
	if value {
		return "yes"
	}
	return "no"
}

// parseCompositeIntID parses colon-separated positive identifiers.
func parseCompositeIntID(id string, parts int) ([]int, error) {
	tokens := strings.Split(id, ":")
	if parts < 1 || len(tokens) != parts {
		return nil, fmt.Errorf("invalid ID %q: expected %d colon-separated positive integers", id, parts)
	}
	result := make([]int, parts)
	for i, token := range tokens {
		n, err := strconv.Atoi(token)
		if err != nil || n < 1 || strings.IndexFunc(token, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, fmt.Errorf("invalid ID %q: each part must be a positive integer", id)
		}
		result[i] = n
	}
	return result, nil
}
