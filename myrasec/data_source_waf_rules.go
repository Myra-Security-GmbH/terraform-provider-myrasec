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

func dataSourceMyrasecWAFRules() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecWAFRulesRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"subdomain_name": {
							Type:     schema.TypeString,
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
						"subdomain_name": {
							Type:     schema.TypeString,
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
						"rule_type": {
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
						"template": {
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

//
// dataSourceMyrasecWAFRulesRead ...
//
func dataSourceMyrasecWAFRulesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareWAFRuleFilter(d.Get("filter"))
	if f == nil {
		f = &wafRuleFilter{}
	}

	params := map[string]string{}
	if len(f.search) > 0 {
		params["search"] = f.search
	}

	if len(f.subDomainName) > 0 {
		params["subDomain"] = f.subDomainName
	}

	rules, diags := listWAFRules(meta, f.subDomainName, params)
	if diags.HasError() {
		return diags
	}

	ruleData := make([]interface{}, 0)
	for _, r := range rules {
		data := map[string]interface{}{
			"id":             r.ID,
			"created":        r.Created.Format(time.RFC3339),
			"modified":       r.Modified.Format(time.RFC3339),
			"subdomain_name": r.SubDomainName,
			"description":    r.Description,
			"direction":      r.Direction,
			"enabled":        r.Enabled,
			"log_identifier": r.LogIdentifier,
			"name":           r.Name,
			"process_next":   r.ProcessNext,
			"rule_type":      r.RuleType,
			"sort":           r.Sort,
			"sync":           r.Sync,
			"template":       r.Template,
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

//
// listWAFRules ..
//
func listWAFRules(meta interface{}, subDomainName string, params map[string]string) ([]myrasec.WAFRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var rules []myrasec.WAFRule
	pageSize := 250

	client := meta.(*myrasec.API)

	domain, err := fetchDomainForSubdomainName(client, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   err.Error(),
		})
		return rules, diags
	}

	params["pageSize"] = strconv.Itoa(pageSize)

	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListWAFRules(domain.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching WAF rules",
				Detail:   err.Error(),
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

//
// prepareWAFRuleFilter ...
//
func prepareWAFRuleFilter(d interface{}) *wafRuleFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareWAFRuleFilter", r)
		}
	}()

	return parseWAFRuleFilter(d)
}

//
// parseWAFRuleFilter ...
//
func parseWAFRuleFilter(d interface{}) *wafRuleFilter {
	cfg := d.([]interface{})
	f := &wafRuleFilter{}

	m := cfg[0].(map[string]interface{})

	subDomainName, ok := m["subdomain_name"]
	if ok {
		f.subDomainName = subDomainName.(string)
	}

	search, ok := m["search"]
	if ok {
		f.search = search.(string)
	}

	return f
}

//
// wafRuleFilter ...
//
type wafRuleFilter struct {
	subDomainName string
	search        string
}
