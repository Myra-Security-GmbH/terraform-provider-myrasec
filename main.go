package main

import (
	"context"
	"flag"
	"log"

	"github.com/Myra-Security-GmbH/terraform-provider-myrasec/myrasec"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	opts := &plugin.ServeOpts{
		ProviderFunc: myrasec.Provider,
	}

	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	if debugMode {
		err := plugin.Debug(context.Background(), "Myra-Security-GmbH/myrasec", opts)
		if err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	plugin.Serve(opts)
}
