package myrasec

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// findDomainIDByDomainName ...
func findDomainIDByDomainName(d *schema.ResourceData, meta interface{}, domainName string) (domainID int, diags diag.Diagnostics) {

	stateDomainID, ok := d.GetOk("domain_id")

	if !ok {
		client := meta.(*myrasec.API)
		domain, err := client.FetchDomain(domainName)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching domain for given domain name",
				Detail:   formatError(err),
			})
			return 0, diags
		}
		domainID = domain.ID
	} else {
		domainID = stateDomainID.(int)
	}

	return domainID, diags
}

// findDomainID ...
func findDomainID(d *schema.ResourceData, meta interface{}) (domainID int, diags diag.Diagnostics) {

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
func findSubdomainNameAndDomainID(d *schema.ResourceData, meta interface{}) (domainID int, subDomainName string, diags diag.Diagnostics) {

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

	if !ok {
		domain, diags := findDomainBySubdomainName(meta, subDomainName)
		if diags.HasError() || domain == nil {
			return 0, subDomainName, diags
		}
		domainID = domain.ID
	} else {
		domainID = stateDomainID.(int)
	}

	return domainID, subDomainName, diags
}

// findDomainBySubdomainName ...
func findDomainBySubdomainName(meta interface{}, subDomainName string) (*myrasec.Domain, diag.Diagnostics) {
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
