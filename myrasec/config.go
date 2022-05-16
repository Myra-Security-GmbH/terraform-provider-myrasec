package myrasec

import (
	"fmt"

	"github.com/Myra-Security-GmbH/terraform-provider-myrasec/version"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"

	"github.com/hashicorp/go-multierror"
)

//
// Config ...
//
type Config struct {
	APIKey     string
	Secret     string
	Language   string
	APIBaseURL string
}

//
// validate ...
//
func (c Config) validate() error {
	var err *multierror.Error

	if c.APIKey == "" {
		err = multierror.Append(err, fmt.Errorf("API Key must be configured for the Myrasec provider"))
	}
	if c.Secret == "" {
		err = multierror.Append(err, fmt.Errorf("API Secret must be configured for the Myrasec provider"))
	}

	if c.APIBaseURL == "" {
		err = multierror.Append(err, fmt.Errorf("API base URL must be configured for the Myrasec provider"))
	}

	return err.ErrorOrNil()
}

//
// Client returns a new instance of myrasec API client
//
func (c Config) Client() (*myrasec.API, error) {
	api, err := myrasec.New(c.APIKey, c.Secret)
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

	api.EnableCaching()
	return api, nil
}
