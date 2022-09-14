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

// dataSourceMyrasecTagWAFRules ...
func dataSourceMyrasecTagWAFRules() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecTagWAFRulesRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tag_id": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"search": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"waf_rules": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tag_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
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
						"expire_date": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"log_identifier": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"direction": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"sort": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"sync": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"process_next": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"conditions": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"force_custom_values": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"available_phases": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"alias": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"category": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"matching_type": {
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
									"value": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
						"actions": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"force_custom_values": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"available_phases": {
										Type:     schema.TypeInt,
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
									"custom_key": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"value": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
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

// dataSourceMyrasecTagWAFRulesRead ...
func dataSourceMyrasecTagWAFRulesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareTagWAFRuleFilter(d.Get("filter"))
	if f == nil {
		f = &tagWafRuleFilter{}
	}

	params := map[string]string{}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	rules, diags := listTagWAFRules(meta, f.tagID, params)
	if diags.HasError() {
		return diags
	}

	ruleData := make([]interface{}, 0)
	for _, r := range rules {
		data := map[string]interface{}{
			"id":             r.ID,
			"created":        r.Created.Format(time.RFC3339),
			"modified":       r.Modified.Format(time.RFC3339),
			"tag_id":         r.TagId,
			"name":           r.Name,
			"description":    r.Description,
			"direction":      r.Direction,
			"log_identifier": r.LogIdentifier,
			"sort":           r.Sort,
			"sync":           r.Sync,
			"process_next":   r.ProcessNext,
			"enabled":        r.Enabled,
			"actions":        r.Actions,
			"conditions":     r.Conditions,
		}

		if r.ExpireDate != nil {
			data["expire_date"] = r.ExpireDate.Format(time.RFC3339)
		}

		if r.Conditions != nil && len(r.Conditions) > 0 {
			conditions := make([]map[string]interface{}, 0)
			for _, c := range r.Conditions {
				conditions = append(conditions, map[string]interface{}{
					"force_custom_values": c.ForceCustomValues,
					"available_phases":    c.AvailablePhases,
					"alias":               c.Alias,
					"category":            c.Category,
					"matching_type":       c.MatchingType,
					"name":                c.Name,
					"key":                 c.Key,
					"value":               c.Value,
				})
			}
			data["conditions"] = conditions
		}

		if r.Actions != nil && len(r.Actions) > 0 {
			actions := make([]map[string]interface{}, 0)
			for _, a := range r.Actions {
				actions = append(actions, map[string]interface{}{
					"force_custom_values": a.ForceCustomValues,
					"available_phases":    a.AvailablePhases,
					"name":                a.Name,
					"type":                a.Type,
					"custom_key":          a.CustomKey,
					"value":               a.Value,
				})
			}
			data["actions"] = actions
		}

		ruleData = append(ruleData, data)
	}

	if err := d.Set("waf_rules", ruleData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

// listTagWAFRules ..
func listTagWAFRules(meta interface{}, tagID int, params map[string]string) ([]myrasec.TagWAFRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var rules []myrasec.TagWAFRule
	pageSize := 250

	client := meta.(*myrasec.API)

	tag, err := client.GetTag(tagID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching tag for ID",
			Detail:   formatError(err),
		})
		return rules, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)

	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListTagWAFRules(tag.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching WAF rules",
				Detail:   formatError(err),
			})
			return rules, diags
		}
		rules = append(rules, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return rules, diags

}

// prepareTagWAFRuleFilter ...
func prepareTagWAFRuleFilter(d interface{}) *tagWafRuleFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareTagWAFRuleFilter", r)
		}
	}()

	return parseTagWAFRuleFilter(d)
}

// parseTagWAFRuleFilter ...
func parseTagWAFRuleFilter(d interface{}) *tagWafRuleFilter {
	cfg := d.([]interface{})
	f := &tagWafRuleFilter{}

	m := cfg[0].(map[string]interface{})

	tagID, ok := m["tag_id"]
	if ok {
		f.tagID = tagID.(int)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	return f
}

// wafRuleFilter ...
type tagWafRuleFilter struct {
	tagID  int
	search string
}
