package myrasec

import (
	"fmt"
	"strconv"
	"strings"

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
// fetchDomainForSubdomainName ...
//
func fetchDomainForSubdomainName(client *myrasec.API, subdomain string) (*myrasec.Domain, error) {

	if strings.HasPrefix(subdomain, "ALL-") {
		parts := strings.Split(removeTrailingDot(subdomain), "ALL-")
		if len(parts) == 2 {
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, err
			}
			return fetchDomainById(client, id)
		}
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
		return nil, fmt.Errorf("unable to find domain for passed domain name [%s]", err.Error())
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
