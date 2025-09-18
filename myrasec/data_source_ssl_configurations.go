package myrasec

import (
	"context"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceMyrasecSSLConfigurations() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecSSLConfigurationsRead,
		Schema: map[string]*schema.Schema{
			"configurations": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ciphers": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"protocols": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

func dataSourceMyrasecSSLConfigurationsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	configurations, diags := listSslConfigurations(meta)
	if diags.HasError() {
		return diags
	}

	configurationsData := make([]any, 0)
	for _, c := range configurations {
		data := map[string]any{
			"name":      c.Name,
			"ciphers":   c.Ciphers,
			"protocols": c.Protocols,
		}
		configurationsData = append(configurationsData, data)
	}

	if err := d.Set("configurations", configurationsData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

func listSslConfigurations(meta any) ([]myrasec.SslConfiguration, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	res, err := client.ListSslConfigurations()
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching SSLConfigurations",
			Detail:   formatError(err),
		})
	}

	return res, diags
}
