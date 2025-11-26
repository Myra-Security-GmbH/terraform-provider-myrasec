package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceMyrasecApiKeys() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecApiKeysRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"keys": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"modified": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"key": {
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

// dataSourceMyrasecApiKeysRead ...
func dataSourceMyrasecApiKeysRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	f := prepareApiKeyFilter(d.Get("filter"))
	if f == nil {
		f = &apiKeyFilter{}
	}

	params := map[string]string{}
	if len(f.name) > 0 {
		params["search"] = f.name
	}

	keys, diags := listApiKeys(meta, params)
	if diags.HasError() {
		return diags
	}

	keysData := make([]any, 0)
	for _, r := range keys {
		keysData = append(keysData, map[string]any{
			"id":       r.ID,
			"created":  r.Created.Format(time.RFC3339),
			"modified": r.Modified.Format(time.RFC3339),
			"name":     r.Name,
			"key":      r.Key,
		})
	}

	if err := d.Set("keys", keysData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil

}

// prepareApiKeyFilter fetches the panic that can happen in parseApiKeyFilter
func prepareApiKeyFilter(d any) *apiKeyFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareApiKeyFilter", r)
		}
	}()

	return parseApiKeyFilter(d)
}

// parseApiKeyFilter converts the filter data to a apiKeyFilter struct
func parseApiKeyFilter(d any) *apiKeyFilter {
	cfg := d.([]any)
	f := &apiKeyFilter{}

	m := cfg[0].(map[string]any)

	name, ok := m["name"]
	if ok {
		f.name = name.(string)
	}

	return f
}

// listApiKeys ...
func listApiKeys(meta any, params map[string]string) ([]myrasec.APIKey, diag.Diagnostics) {
	var diags diag.Diagnostics
	var keys []myrasec.APIKey
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListApiKeys(params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching API keys",
				Detail:   formatError(err),
			})
			return keys, diags
		}
		keys = append(keys, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return keys, diags
}

// apiKeyFilter struct ...
type apiKeyFilter struct {
	name string
}
