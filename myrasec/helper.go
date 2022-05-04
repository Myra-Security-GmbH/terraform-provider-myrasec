package myrasec

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
)

//
// parseResourceServiceID splits the passed id (format like string:integer) to separate values
//
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

//
// StringInSlice checks if the haystack []string slice contains the passed needle string
//
func StringInSlice(needle string, haystack []string) bool {
	for _, a := range haystack {
		if a == needle {
			return true
		}
	}
	return false
}

//
// IntInSlice checks if the haystack []int slice contains the passed needle int
//
func IntInSlice(needle int, haystack []int) bool {
	for _, a := range haystack {
		if a == needle {
			return true
		}
	}
	return false
}

//
// isGeneralDomainName checks if the passed name starts with ALL- or ALL:
//
func isGeneralDomainName(name string) bool {
	name = strings.ToUpper(name)
	return strings.HasPrefix(name, "ALL-") || strings.HasPrefix(name, "ALL:")
}

//
// fetchDomainForSubdomainName ...
//
func fetchDomainForSubdomainName(client *myrasec.API, subdomain string) (*myrasec.Domain, error) {

	if isGeneralDomainName(subdomain) {
		var parts []string
		name := removeTrailingDot(subdomain)
		if strings.HasPrefix(name, "ALL-") {
			parts = strings.Split(name, "ALL-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("wrong format for ALL-<DOMAIN_ID> annotation")
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, err
			}
			return fetchDomainById(client, id)
		}

		parts = strings.Split(name, "ALL:")
		if len(parts) != 2 {
			return nil, fmt.Errorf("wrong format for ALL:<DOMAIN_NAME> annotation")
		}

		return fetchDomain(client, parts[1])
	}

	subdomains, err := client.ListAllSubdomains(map[string]string{"search": subdomain})
	if err != nil {
		return nil, err
	}

	domainNames := make(map[string]bool)
	for _, s := range subdomains {
		domainNames[s.DomainName] = true
	}

	for dn := range domainNames {
		domains, err := client.ListDomains(map[string]string{"search": dn})
		if err != nil {
			return nil, err
		}

		for _, d := range domains {
			vhosts, err := client.ListAllSubdomainsForDomain(d.ID, map[string]string{"search": subdomain})
			if err != nil {
				return nil, err
			}

			for _, vh := range vhosts {
				if ensureTrailingDot(vh.Label) == ensureTrailingDot(subdomain) {
					return &d, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("unable to find domain for passed subdomain")
}

//
// fetchDomain ...
//
func fetchDomain(client *myrasec.API, domain string) (*myrasec.Domain, error) {

	domains, err := client.ListDomains(map[string]string{"search": domain})
	if err != nil {
		return nil, err
	}

	for _, d := range domains {
		if d.Name == domain {
			return &d, nil
		}
	}

	d, err := fetchDomainForSubdomainName(client, domain)
	if err != nil {
		return nil, fmt.Errorf("unable to find domain for passed domain name [%s]", domain)
	}

	return d, nil
}

//
// fetchDomainById ...
//
func fetchDomainById(client *myrasec.API, id int) (*myrasec.Domain, error) {
	domains, err := client.ListDomains(nil)
	if err != nil {
		return nil, err
	}

	for _, d := range domains {
		if d.ID == id {
			return &d, nil
		}
	}

	return nil, fmt.Errorf("unable to find domain for passed domain ID [%d]", id)
}

//
// ensureTrailingDot ...
//
func ensureTrailingDot(subdomain string) string {
	return removeTrailingDot(subdomain) + "."
}

//
// removeTrailingDot ...
//
func removeTrailingDot(subdomain string) string {
	return strings.TrimRight(subdomain, ".")
}

//
// formatError returns the error message with a timestamp appended to it
//
func formatError(err error) string {
	return fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339Nano), err.Error())
}
