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

// dataSourceMyrasecWAFActions ...
func dataSourceMyrasecWAFActions() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecWAFActionsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"waf_actions": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"available_phases": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"force_custom_values": {
							Type:     schema.TypeBool,
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

// dataSourceMyrasecWAFActionsRead ...
func dataSourceMyrasecWAFActionsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	f := prepareWAFActionFilter(d.Get("filter"))

	actions, err := client.ListWAFActions()
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching WAF actions",
			Detail:   formatError(err),
		})
		return diags
	}

	wafActionData := make([]any, 0)
	for _, r := range actions {
		if f != nil && r.Type != f.actionType {
			continue
		}

		wafActionData = append(wafActionData, map[string]any{
			"created":             r.Created.Format(time.RFC3339),
			"modified":            r.Modified.Format(time.RFC3339),
			"name":                r.Name,
			"available_phases":    r.AvailablePhases,
			"force_custom_values": r.ForceCustomValues,
			"type":                r.Type,
		})
	}

	if err := d.Set("waf_actions", wafActionData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

// prepareWAFActionFilter fetches the panic that can happen in parseWAFActionFilter
func prepareWAFActionFilter(d any) *wafActionFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareWAFActionFilter", r)
		}
	}()

	return parseWAFActionFilter(d)
}

// parseWAFActionFilter ...
func parseWAFActionFilter(d any) *wafActionFilter {
	cfg := d.([]any)
	f := &wafActionFilter{}

	m := cfg[0].(map[string]any)

	actionType, ok := m["type"]
	if ok {
		f.actionType = actionType.(string)
	}

	return f
}

// wafActionFilter struct ...
type wafActionFilter struct {
	actionType string
}
