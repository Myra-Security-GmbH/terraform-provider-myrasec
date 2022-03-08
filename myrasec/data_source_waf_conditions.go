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

//
// dataSourceMyrasecWAFConditions ...
//
func dataSourceMyrasecWAFConditions() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecWAFConditionsRead,
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
			"waf_conditions": {
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
						"matching_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"alias": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"key": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"category": {
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

//
// dataSourceMyrasecWAFConditionsRead ...
//
func dataSourceMyrasecWAFConditionsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	f := prepareWAFConditionFilter(d.Get("filter"))

	conditions, err := client.ListWAFConditions()
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching WAF conditions",
			Detail:   err.Error(),
		})
		return diags
	}

	wafConditionData := make([]interface{}, 0)
	for _, r := range conditions {
		if f != nil && r.Name != f.name {
			continue
		}

		wafConditionData = append(wafConditionData, map[string]interface{}{
			"id":                  r.ID,
			"created":             r.Created.Format(time.RFC3339),
			"modified":            r.Modified.Format(time.RFC3339),
			"name":                r.Name,
			"matching_type":       r.MatchingType,
			"alias":               r.Alias,
			"key":                 r.Key,
			"value":               r.Value,
			"category":            r.Category,
			"available_phases":    r.AvailablePhases,
			"force_custom_values": r.ForceCustomValues,
		})
	}

	if err := d.Set("waf_conditions", wafConditionData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

//
// prepareRedirectFilter fetches the panic that can happen in parseWAFConditionFilter
//
func prepareWAFConditionFilter(d interface{}) *wafConditionFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareWAFConditionFilter", r)
		}
	}()

	return parseWAFConditionFilter(d)
}

//
// parseWAFConditionFilter ...
//
func parseWAFConditionFilter(d interface{}) *wafConditionFilter {
	cfg := d.([]interface{})
	f := &wafConditionFilter{}

	m := cfg[0].(map[string]interface{})

	name, ok := m["name"]
	if ok {
		f.name = name.(string)
	}

	return f
}

//
// wafConditionFilter struct...
//
type wafConditionFilter struct {
	name string
}
