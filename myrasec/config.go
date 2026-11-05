package myrasec

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/Myra-Security-GmbH/terraform-provider-myrasec/version"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"

	"github.com/hashicorp/go-multierror"
)

// Config ...
type Config struct {
	APIKey            string
	Secret            string
	APIToken          string
	Language          string
	APIBaseURL        string
	APICacheTTL       int
	APIRetryCount     int
	APIRetrySleep     int
	AllowInsecureHTTP bool
}

// validate ...
func (c Config) validate() error {
	var err *multierror.Error

	hasToken := c.APIToken != ""

	if !hasToken && c.APIKey == "" && c.Secret == "" {
		err = multierror.Append(err, fmt.Errorf("API token or API Key and API Secret is required for using the Myrasec provider"))
	}

	if !hasToken && c.APIKey == "" {
		err = multierror.Append(err, fmt.Errorf("API Key must be configured for the Myrasec provider"))
	}
	if !hasToken && c.Secret == "" {
		err = multierror.Append(err, fmt.Errorf("API Secret must be configured for the Myrasec provider"))
	}

	if c.APIBaseURL == "" {
		err = multierror.Append(err, fmt.Errorf("API base URL must be configured for the Myrasec provider"))
	} else if urlErr := validateAPIBaseURL(c.APIBaseURL, c.AllowInsecureHTTP); urlErr != nil {
		err = multierror.Append(err, urlErr)
	}

	return err.ErrorOrNil()
}

// validateAPIBaseURL checks the configured API base URL: it must carry the %s placeholder for
// the API method, name a host and use https. Plain http is accepted for the local machine and,
// with allow_insecure_http, for any host.
func validateAPIBaseURL(baseURL string, allowInsecureHTTP bool) error {
	if !strings.Contains(baseURL, "%s") {
		return fmt.Errorf("API base URL must contain the %%s placeholder for the API method, for example %s", myrasec.APIBaseURL)
	}

	// url.Parse rejects the placeholder as a broken escape sequence
	u, err := url.Parse(strings.ReplaceAll(baseURL, "%s", "method"))
	if err != nil {
		return fmt.Errorf("API base URL is not a valid URL: %w", err)
	}

	if u.Host == "" {
		return fmt.Errorf("API base URL must name a host, for example %s", myrasec.APIBaseURL)
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecureHTTP || isLoopbackHost(u.Hostname()) {
			return nil
		}

		return fmt.Errorf("API base URL uses plain http, the API credentials would be sent in clear text: use https or set allow_insecure_http = true for a test endpoint")
	default:
		return fmt.Errorf("API base URL must use https, got scheme %q", u.Scheme)
	}
}

// isLoopbackHost reports whether host names the local machine: localhost or a loopback IP
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// Client returns a new instance of myrasec API client
func (c Config) Client() (*myrasec.API, error) {
	var api *myrasec.API
	var err error
	if c.APIToken != "" {
		api, err = myrasec.NewWithToken(c.APIToken)
	} else {
		api, err = myrasec.New(c.APIKey, c.Secret)
	}
	if err != nil {
		return nil, err
	}

	err = api.SetLanguage(c.Language)
	if err != nil {
		return nil, err
	}

	userAgent := fmt.Sprintf("terraform-provider-myrasec_%s", version.ProviderVersion)
	api.SetUserAgent(userAgent)

	api.BaseURL = c.APIBaseURL
	api.SetInsecureHTTP(c.AllowInsecureHTTP)

	if c.APICacheTTL > 0 {
		api.EnableCaching()
		api.SetCachingTTL(c.APICacheTTL)
	}

	if c.APIRetryCount > myrasec.DefaultRetryCount {
		api.SetMaxRetries(c.APIRetryCount)
	}
	if c.APIRetrySleep > myrasec.DefaultRetrySleep {
		api.SetRetrySleep(c.APIRetrySleep)
	}

	return api, nil
}
