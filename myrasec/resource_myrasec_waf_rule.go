package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceMyrasecWAFRule() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecWAFRuleCreate,
		ReadContext:   resourceMyrasecWAFRuleRead,
		UpdateContext: resourceMyrasecWAFRuleUpdate,
		DeleteContext: resourceMyrasecWAFRuleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecWAFRuleImport,
		},
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					name := i.(string)
					if myrasec.IsGeneralDomainName(name) {
						return name
					}
					return strings.ToLower(name)
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new)
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
				Description: "Expire date schedules the deaktivation of the WAF rule. If none is set, the rule will be active until manual deactivation.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The rule name identifies each rule.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Your notes on this rule.",
			},
			"log_identifier": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "A comment to identify the matching rule in the access log.",
			},
			"direction": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				ValidateFunc: validation.StringInSlice([]string{"in", "out"}, false),
				Description:  "Phase specifies the condition under which a rule applies. Pre-origin means before your server (request), post-origin is past your server (response).",
			},
			"sort": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1,
				Description: "The order in which the rules take action.",
			},
			"sync": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "",
			},
			"template": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "",
			},
			"process_next": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "After a rule has been applied, the rule chain will be executed as determined.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Define wether this rule is enabled or not.",
			},
			"conditions": {
				Type:     schema.TypeList,
				Required: true,
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
							Required: true,
						},
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"actions": {
				Type:     schema.TypeList,
				Required: true,
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
							Required: true,
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

// resourceMyrasecWAFRuleCreate ...
func resourceMyrasecWAFRuleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	rule, err := buildWAFRule(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building WAF rule",
			Detail:   formatError(err),
		})
		return diags
	}

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := client.FetchDomainForSubdomainName(subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	resp, err := client.CreateWAFRule(rule, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating WAF rule",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecWAFRuleRead(ctx, d, meta)
}

// resourceMyrasecWAFRuleRead ...
func resourceMyrasecWAFRuleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("subdomain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[subdomain_name] is not set")),
		})
		return diags
	}

	subDomainName := name.(string)
	ruleID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing WAF rule ID",
			Detail:   formatError(err),
		})
		return diags
	}

	rule, diags := findWAFRule(ruleID, meta, subDomainName)
	if diags.HasError() || rule == nil {
		return diags
	}

	setWAFRuleData(d, rule)

	return diags
}

// resourceMyrasecWAFRuleUpdate ...
func resourceMyrasecWAFRuleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	ruleID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing WAF rule ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating WAF rule: %v", ruleID)

	rule, err := buildWAFRule(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building WAF rule",
			Detail:   formatError(err),
		})
		return diags
	}

	subDomainName := d.Get("subdomain_name").(string)
	domain, err := client.FetchDomainForSubdomainName(subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return diags
	}

	// REMOVEME
	// NOTE: This is a temporary "fix"
	time.Sleep(200 * time.Millisecond)

	rule, err = client.UpdateWAFRule(rule, domain.ID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating WAF rule",
			Detail:   formatError(err),
		})
		return diags
	}

	setWAFRuleData(d, rule)

	return diags
}

// resourceMyrasecWAFRuleDelete ...
func resourceMyrasecWAFRuleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	ruleID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing WAF rule ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting WAF rule: %v", ruleID)

	rule, err := buildWAFRule(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building WAF rule",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.DeleteWAFRule(rule)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting WAF rule",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecWAFRuleImport ...
func resourceMyrasecWAFRuleImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	subDomainName, ruleID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing WAF rule ID: [%s]", err.Error())
	}

	rule, diags := findWAFRule(ruleID, meta, subDomainName)
	if diags.HasError() || rule == nil {
		return nil, fmt.Errorf("unable to find WAF rule for subdomain [%s] with ID = [%d]", subDomainName, ruleID)
	}

	d.SetId(strconv.Itoa(ruleID))
	d.Set("rule_id", rule.ID)
	d.Set("subdomain_name", rule.SubDomainName)

	resourceMyrasecWAFRuleRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildWAFRule ...
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
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			rule.ID = id
		}
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

// buildWAFCondition ...
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
		case "alias":
			c.Alias = val.(string)
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

// buildWAFAction ...
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
		case "force_custom_values":
			a.ForceCustomValues = val.(bool)
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

// findWAFRule ...
func findWAFRule(wafRuleID int, meta interface{}, subDomainName string) (*myrasec.WAFRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	domain, err := client.FetchDomainForSubdomainName(subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching domain for given subdomain name",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	page := 1
	pageSize := 250
	params := map[string]string{
		"subDomain": myrasec.EnsureTrailingDot(subDomainName),
		"pageSize":  strconv.Itoa(pageSize),
		"page":      strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListWAFRules(domain.ID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading WAF rules",
				Detail:   formatError(err),
			})
			return nil, diags
		}

		for _, r := range res {
			if r.ID == wafRuleID {
				return &r, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find WAF rule",
		Detail:   fmt.Sprintf("Unable to find WAF rule with ID = [%d]", wafRuleID),
	})
	return nil, diags
}

// setWAFRuleData ...
func setWAFRuleData(d *schema.ResourceData, rule *myrasec.WAFRule) {
	d.SetId(strconv.Itoa(rule.ID))
	d.Set("rule_id", rule.ID)
	d.Set("created", rule.Created.Format(time.RFC3339))
	d.Set("modified", rule.Modified.Format(time.RFC3339))
	d.Set("subdomain_name", rule.SubDomainName)
	d.Set("name", rule.Name)
	d.Set("description", rule.Description)
	d.Set("log_identifier", rule.LogIdentifier)
	d.Set("direction", rule.Direction)
	d.Set("sort", rule.Sort)
	d.Set("sync", rule.Sync)
	d.Set("process_next", rule.ProcessNext)
	d.Set("enabled", rule.Enabled)

	conditions := []interface{}{}
	for _, condition := range rule.Conditions {

		c := map[string]interface{}{
			"condition_id":  condition.ID,
			"alias":         condition.Alias,
			"category":      condition.Category,
			"matching_type": condition.MatchingType,
			"name":          condition.Name,
			"key":           condition.Key,
			"value":         condition.Value,
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
	for _, action := range rule.Actions {
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
}
