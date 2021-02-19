package main

import (
	"github.com/Myra-Security-GmbH/terraform-provider-myrasec/myrasec"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	opts := &plugin.ServeOpts{
		ProviderFunc: myrasec.Provider,
	}

	plugin.Serve(opts)
}
