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

var requiredActionValue = []string{
	"remove_header",
	"change_upstream",
	"del_qs_param",
}
var requiredActionKeyValue = []string{
	"modify_header",
	"add_header",
	"origin_rate_limit",
	"score",
	"uri_subst",
	"set_http_status",
	"remove_header_value_regex",
}
var requiredConditionKey = []string{
	"custom_header",
	"cookie",
	"arg",
	"postarg",
}
var requiredConditionValue = []string{
	"score",
}
var notAllowedResponseActions = []string{
	"block",
	"allow",
	"log",
	"verify_human",
	"del_qs_param",
}
var processNextForbiddenActions = []string{
	"block",
	"allow",
}

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
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Stores domain Id for subdomain.",
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
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"condition_id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "ID of the WAF rule condition.",
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
		CustomizeDiff: func(ctx context.Context, rd *schema.ResourceDiff, i interface{}) error {
			err := validateActions(rd)
			if err != nil {
				return err
			}

			err = validateConditions(rd)
			if err != nil {
				return err
			}
			return nil
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

func validateActions(rd *schema.ResourceDiff) error {
	actions := rd.Get("actions").([]interface{})
	for _, v := range actions {
		a := v.(map[string]interface{})
		direction := rd.Get("direction").(string)
		if direction == "out" {
			for _, r := range notAllowedResponseActions {
				if r == a["type"] {
					return fmt.Errorf("action type `%s` is not allowed on direction `out`", a["type"])
				}
			}
		} else {
			processNext := rd.Get("process_next").(bool)
			for _, r := range processNextForbiddenActions {
				if r == a["type"] && processNext {
					return fmt.Errorf("action type `%s` is not allowed when process_next is true", a["type"])
				}
			}
		}
		for _, r := range requiredActionValue {
			if r == a["type"] && a["value"] == "" {
				return fmt.Errorf("value is required for action %s", a["type"])
			}
		}
		for _, r := range requiredActionKeyValue {
			if r == a["type"] && (a["custom_key"] == "" || a["value"] == "") {
				return fmt.Errorf("custom_key and value are required for action %s", a["type"])
			}
		}
		if a["type"] == "score" {
			keys := []string{"+", "-", "*"}
			if !StringInSlice(a["custom_key"].(string), keys) {
				return fmt.Errorf("score key has to one of '+', '-', '*'")
			}
			_, err := strconv.Atoi(a["value"].(string))
			if err != nil {
				return fmt.Errorf("score values has to be a number")
			}
		}
		if a["type"] == "origin_rate_limit" {
			values := []int{1, 2, 5, 10, 15, 30, 45, 60, 120, 180, 300, 600, 1200, 3600, 10800, 21600, 43200, 64800, 86400}
			key, err := strconv.Atoi(a["custom_key"].(string))
			if err != nil {
				return fmt.Errorf("origin_rate_limit custom_key must be a number")
			}
			valid := IntInSlice(key, values)
			if !valid {
				return fmt.Errorf(fmt.Sprintf("origin_rate_limit customKey must be one of %s", strings.Join(strings.Fields(fmt.Sprint(values)), ", ")))
			}
			_, err = strconv.Atoi(a["value"].(string))
			if err != nil {
				return fmt.Errorf("origin_rate_limit value must be a number")
			}
		}
		if a["type"] == "set_http_status" {
			values := []int{301, 302, 404}
			key, err := strconv.Atoi(a["custom_key"].(string))
			if err != nil {
				return fmt.Errorf("set_http_status custom_key must be a number")
			}
			valid := IntInSlice(key, values)
			if !valid {
				return fmt.Errorf(fmt.Sprintf("set_http_status customKey must be one of %s", strings.Join(strings.Fields(fmt.Sprint(values)), ", ")))
			}
		}
	}
	return nil
}

func validateConditions(rd *schema.ResourceDiff) error {
	conditions := rd.Get("conditions").([]interface{})
	for _, v := range conditions {
		c := v.(map[string]interface{})
		for _, r := range requiredConditionKey {
			if r == c["name"] && c["key"] == "" {
				return fmt.Errorf("key is required for condition %s", c["name"])
			}
		}
		for _, r := range requiredConditionValue {
			if r == c["name"] && c["value"] == "" {
				return fmt.Errorf("value is required for condition %s", c["name"])
			}
		}
		if c["name"] == "score" {
			_, err := strconv.Atoi(c["value"].(string))
			if err != nil {
				return fmt.Errorf("score value has to be a number")
			}
		}
	}
	return nil
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

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	resp, err := client.CreateWAFRule(rule, domainID, subDomainName)
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

	ruleID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing WAF rule ID",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	rule, diags := findWAFRule(ruleID, meta, subDomainName, domainID)
	if diags.HasError() || rule == nil {
		return diags
	}

	setWAFRuleData(d, rule, domainID)

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

	domainID, subDomainName, diags := findSubdomainNameAndDomainID(d, meta)
	if diags.HasError() {
		return diags
	}

	rule, err = client.UpdateWAFRule(rule, domainID, subDomainName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating WAF rule",
			Detail:   formatError(err),
		})
		return diags
	}

	setWAFRuleData(d, rule, domainID)

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

	domain, diags := findDomainBySubdomainName(meta, subDomainName)
	if diags != nil {
		return nil, fmt.Errorf("unable to find domain for subdomain: [%s]", subDomainName)
	}

	rule, diags := findWAFRule(ruleID, meta, subDomainName, domain.ID)
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
	date := d.Get("expire_date").(string)
	expireDate, err := types.ParseDate(date)
	if err != nil {
		return nil, err
	}
	rule.ExpireDate = expireDate

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
		rule.Conditions = make([]*myrasec.WAFCondition, 0)
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
		case "name":
			a.Name = val.(string)
		case "type":
			a.Type = val.(string)
		case "custom_key":
			a.CustomKey = val.(string)
		case "value":
			a.Value = val.(string)
		}
	}

	return a, nil
}

// findWAFRule ...
func findWAFRule(wafRuleID int, meta interface{}, subDomainName string, domainID int) (*myrasec.WAFRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	pageSize := 250
	params := map[string]string{
		"subDomain": myrasec.EnsureTrailingDot(subDomainName),
		"pageSize":  strconv.Itoa(pageSize),
		"page":      strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListWAFRules(domainID, params)
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
func setWAFRuleData(d *schema.ResourceData, rule *myrasec.WAFRule, domainID int) {
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
	d.Set("process_next", rule.ProcessNext)
	d.Set("enabled", rule.Enabled)
	d.Set("domain_id", domainID)
	d.Set("rule_type", rule.RuleType)

	conditions := createConditions(rule.Conditions)
	d.Set("conditions", conditions)

	actions := createActions(rule.Actions)
	d.Set("actions", actions)
}

func createConditions(ruleConditions []*myrasec.WAFCondition) []interface{} {
	conditions := []interface{}{}
	for _, condition := range ruleConditions {
		c := map[string]interface{}{
			"condition_id":     condition.ID,
			"alias":            condition.Alias,
			"category":         condition.Category,
			"matching_type":    condition.MatchingType,
			"name":             condition.Name,
			"key":              condition.Key,
			"value":            condition.Value,
			"available_phases": condition.AvailablePhases,
		}
		conditions = append(conditions, c)
	}
	return conditions
}

func createActions(ruleActions []*myrasec.WAFAction) []interface{} {
	actions := []interface{}{}
	for _, action := range ruleActions {
		a := map[string]interface{}{
			"available_phases": action.AvailablePhases,
			"name":             action.Name,
			"type":             action.Type,
			"value":            action.Value,
			"custom_key":       action.CustomKey,
		}
		actions = append(actions, a)
	}
	return actions
}
