package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/Myra-Security-GmbH/myrasec-go/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceMyrasecWAFRule() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecWAFRuleCreate,
		ReadContext:   resourceMyrasecWAFRuleRead,
		DeleteContext: resourceMyrasecWAFRuleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the WAF rule.",
			},
			"rule_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the WAF rule.",
			},
			"modified": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date of last modification.",
			},
			"created": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date of creation.",
			},
			"rule_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Type of the rule.",
			},
			"expire_date": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Expire date schedules the deaktivation of the WAF rule. If none is set, the rule will be active until manual deactivation.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The rule name identifies each rule.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				ForceNew:    true,
				Description: "Your notes on this rule.",
			},
			"log_identifier": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				ForceNew:    true,
				Description: "A comment to identify the matching rule in the access log.",
			},
			"direction": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				ValidateFunc: validation.StringInSlice([]string{"in", "out"}, false),
				ForceNew:     true,
				Description:  "Phase specifies the condition under which a rule applies. Pre-origin means before your server (request), post-origin is past your server (response).",
			},
			"sort": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1,
				ForceNew:    true,
				Description: "The order in which the rules take action.",
			},
			"sync": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "",
			},
			"template": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "",
			},
			"process_next": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "After a rule has been applied, the rule chain will be executed as determined.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Define wether this rule is enabled or not.",
			},
			"conditions": {
				Type:     schema.TypeList,
				Required: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"condition_id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "ID of the WAF rule condition.",
						},
						"modified": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Date of last modification.",
						},
						"created": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Date of creation.",
						},
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
							Optional: true,
						},
						"category": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"matching_type": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"actions": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"action_id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "ID of the WAF rule.",
						},
						"modified": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Date of last modification.",
						},
						"created": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Date of creation.",
						},
						"force_custom_values": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"available_phases": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"type": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"custom_key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Optional: true,
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
// resourceMyrasecWAFRuleCreate ...
//
func resourceMyrasecWAFRuleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	rule, err := buildWAFRule(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building WAF rule",
			Detail:   err.Error(),
		})
		return diags
	}

	resp, err := client.CreateWAFRule(rule)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating WAF rule",
			Detail:   err.Error(),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecWAFRuleRead(ctx, d, meta)
}

//
// resourceMyrasecWAFRuleRead ...
//
func resourceMyrasecWAFRuleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	subDomainName, ruleID, err := parseResourceServiceID(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing ID",
			Detail:   err.Error(),
		})
		return diags
	}

	rules, err := client.ListWAFRules("domain", map[string]string{"subDomain": subDomainName})
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching WAF rule",
			Detail:   err.Error(),
		})
		return diags
	}

	for _, r := range rules {
		if r.ID != ruleID {
			continue
		}
		d.Set("rule_id", r.ID)
		d.Set("created", r.Created.Format(time.RFC3339))
		d.Set("modified", r.Modified.Format(time.RFC3339))
		d.Set("subdomain_name", r.SubDomainName)
		d.Set("name", r.Name)
		d.Set("description", r.Description)
		d.Set("log_identifier", r.LogIdentifier)
		d.Set("direction", r.Direction)
		d.Set("sort", r.Sort)
		d.Set("sync", r.Sync)
		d.Set("process_next", r.ProcessNext)
		d.Set("enabled", r.Enabled)

		conditions := []interface{}{}
		for _, condition := range r.Conditions {

			c := map[string]interface{}{
				"condition_id":        condition.ID,
				"force_custom_values": condition.ForceCustomValues,
				"available_phases":    condition.AvailablePhases,
				"alias":               condition.Alias,
				"category":            condition.Category,
				"matching_type":       condition.MatchingType,
				"name":                condition.Name,
				"key":                 condition.Key,
				"value":               condition.Value,
			}

			if condition.Created != nil {
				c["created"] = condition.Created.Format(time.RFC3339)
			}

			if condition.Modified != nil {
				c["modified"] = condition.Modified.Format(time.RFC3339)
			}

			conditions = append(conditions, c)
		}
		d.Set("conditions", conditions)

		actions := []interface{}{}
		for _, action := range r.Actions {
			a := map[string]interface{}{
				"action_id":           action.ID,
				"force_custom_values": action.ForceCustomValues,
				"available_phases":    action.AvailablePhases,
				"name":                action.Name,
				"type":                action.Type,
				"value":               action.Value,
				"custom_key":          action.CustomKey,
			}

			if action.Created != nil {
				a["created"] = action.Created.Format(time.RFC3339)
			}

			if action.Modified != nil {
				a["modified"] = action.Modified.Format(time.RFC3339)
			}
			actions = append(actions, a)
		}
		d.Set("actions", actions)

		break
	}

	return diags
}

//
// resourceMyrasecWAFRuleDelete ...
//
func resourceMyrasecWAFRuleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	ruleID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing WAF rule id",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Deleting WAF rule: %v", ruleID)

	rule, err := buildWAFRule(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building WAF rule",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.DeleteWAFRule(rule)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting WAF rule",
			Detail:   err.Error(),
		})
		return diags
	}
	return diags
}

//
// buildWAFRule ...
//
func buildWAFRule(d *schema.ResourceData, meta interface{}) (*myrasec.WAFRule, error) {
	rule := &myrasec.WAFRule{
		SubDomainName: d.Get("subdomain_name").(string),
		Name:          d.Get("name").(string),
		Description:   d.Get("description").(string),
		LogIdentifier: d.Get("log_identifier").(string),
		Direction:     d.Get("direction").(string),
		Sort:          d.Get("sort").(int),
		Sync:          d.Get("sync").(bool),
		ProcessNext:   d.Get("process_next").(bool),
		Enabled:       d.Get("enabled").(bool),
		RuleType:      "domain",
	}

	if d.Get("rule_id").(int) > 0 {
		rule.ID = d.Get("rule_id").(int)
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	rule.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	rule.Modified = modified

	conditions, ok := d.GetOk("conditions")
	if !ok {
		return rule, nil
	}

	for _, condition := range conditions.([]interface{}) {
		c, err := buildWAFCondition(condition)
		if err != nil {
			return nil, err
		}
		rule.Conditions = append(rule.Conditions, c)
	}

	actions, ok := d.GetOk("actions")
	if !ok {
		return rule, nil
	}

	for _, action := range actions.([]interface{}) {
		a, err := buildWAFAction(action)
		if err != nil {
			return nil, err
		}
		rule.Actions = append(rule.Actions, a)

	}

	return rule, nil
}

//
// buildWAFCondition ...
//
func buildWAFCondition(condition interface{}) (*myrasec.WAFCondition, error) {
	c := &myrasec.WAFCondition{}
	for key, val := range condition.(map[string]interface{}) {
		switch key {
		case "condition_id":
			c.ID = val.(int)
		case "modified":
			modified, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			c.Modified = modified
		case "created":
			created, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			c.Created = created
		case "force_custom_values":
			c.ForceCustomValues = val.(bool)
		case "alias":
			c.Alias = val.(string)
		case "available_phases":
			c.AvailablePhases = val.(int)
		case "category":
			c.Category = val.(string)
		case "matching_type":
			c.MatchingType = val.(string)
		case "name":
			c.Name = val.(string)
		case "value":
			c.Value = val.(string)
		case "key":
			c.Key = val.(string)
		}
	}

	return c, nil
}

//
// buildWAFAction ...
//
func buildWAFAction(action interface{}) (*myrasec.WAFAction, error) {
	a := &myrasec.WAFAction{}
	for key, val := range action.(map[string]interface{}) {
		switch key {
		case "action_id":
			a.ID = val.(int)
		case "modified":
			modified, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			a.Modified = modified
		case "created":
			created, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			a.Created = created
		case "name":
			a.Name = val.(string)
		case "type":
			a.Type = val.(string)
		case "available_phases":
			a.AvailablePhases = val.(int)
		case "custom_key":
			a.CustomKey = val.(string)
		case "value":
			a.Value = val.(string)
		}
	}

	return a, nil
}
