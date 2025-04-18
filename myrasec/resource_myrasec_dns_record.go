package myrasec

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// resourceMyrasecDNSRecord ...
func resourceMyrasecDNSRecord() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecDNSRecordCreate,
		ReadContext:   resourceMyrasecDNSRecordRead,
		UpdateContext: resourceMyrasecDNSRecordUpdate,
		DeleteContext: resourceMyrasecDNSRecordDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecDNSRecordImport,
		},
		Schema: map[string]*schema.Schema{
			"domain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Domain for the DNS record.",
			},
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Stores domain Id for subdomain.",
			},
			"record_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the DNS record.",
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
			"name": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					domainName := d.Get("domain_name")
					return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new) || myrasec.RemoveTrailingDot(old) == fmt.Sprintf("%s.%s", new, domainName)
				},
				Description: "Subdomain name of a DNS record.",
			},
			"ttl": {
				Type:     schema.TypeInt,
				Required: true,
				ValidateFunc: func(i interface{}, s string) (warnings []string, errors []error) {

					values := []int{300, 600, 900, 1800, 3600, 7200, 18000, 43200, 86400}

					valid := IntInSlice(i.(int), values)
					if !valid {
						warnings = append(warnings, fmt.Sprintf("value is not a valid ttl, must be one of %s", strings.Join(strings.Fields(fmt.Sprint(values)), ",")))
					}

					return warnings, errors
				},
				Description: "Time to live.",
			},
			"record_type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"A", "AAAA", "MX", "CNAME", "TXT", "NS", "SRV", "CAA", "PTR", "DS"}, false),
				Description:  "A record type to identify the type of a record. Valid types are: A, AAAA, MX, CNAME, TXT, NS, SRV, CAA , PTR and DS.",
			},
			"alternative_cname": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The alternative CNAME that points to the record.",
			},
			"active": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				DiffSuppressFunc: func(k string, old string, new string, d *schema.ResourceData) bool {
					rt, ok := d.GetOk("record_type")
					if !ok {
						return false
					}

					if StringInSlice(rt.(string), []string{"A", "AAAA", "CNAME"}) {
						return false
					}

					return true
				},
				Description: "Define wether this subdomain should be protected by Myra or not.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Define wether this DNS record is enabled or not.",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "A comment to describe this DNS record.",
			},
			"value": {
				Type:     schema.TypeString,
				Required: true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					recordType := d.Get("record_type")

					if recordType == "PTR" {
						return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new)
					} else {
						return old == new
					}
				},
				Description: "Depends on the record type. Typically an IPv4/6 address or a domain entry.",
			},
			"priority": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Priority of MX records.",
				ValidateFunc: validation.IntBetween(0, math.MaxUint16),
			},
			"port": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Port for SRV records.",
			},
			"weight": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Weight for SRV records.",
			},
			"caa_tag": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Tag value for `CAA` records. Available values are `issue`, `issuewild`, `issuemail`, `issuevmc`, `iodef`, `contactemail` and `contactphone`.",
			},
			"caa_flags": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Flags value for `CAA` records.",
			},
			"encryption": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Encryption for `DS` records. Available values are `3` (DSA/SHA1), `5` (RSA/SHA1), `6` (DSA-NSEC3-SHA1), `7` (RSASHA1-NSEC3-SHA1), `8` (RSA/SHA-256), `10` (RSA/SHA-512), `12` (GOST R 35.10-2001), `13` (ECDSA-P256/SHA256), `14` (ECDSA-P384/SHA384), `15` (ED25519) and `16` (ED448).",
			},
			"hash_type": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Hash type for `DS` records. Available values are `1` (SHA-1), `2` (SHA-256), `3` (GOST R 34.11-94) and `4` (SHA-384).",
			},
			"identificationnumber": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "ID (key tag) for `DS` records.",
			},
			"upstream_options": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Optional: true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					oldUpstream, newUpstream := d.GetChange("upstream_options.0")

					uoOld, _ := oldUpstream.(map[string]interface{})
					uoNew, _ := newUpstream.(map[string]interface{})

					maxFailsOld, maxFailsOk := uoOld["max_fails"].(int)
					weighOld, weightOk := uoOld["weight"].(int)

					return maxFailsOk && maxFailsOld == uoNew["max_fails"].(int) &&
						weightOk && weighOld == uoNew["weight"].(int) &&
						uoOld["backup"].(bool) == uoNew["backup"].(bool) &&
						uoOld["down"].(bool) == uoNew["down"].(bool) &&
						uoOld["fail_timeout"].(string) == uoNew["fail_timeout"].(string)
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"upstream_id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "ID of the upstream configuration.",
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
						"backup": {
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     false,
							Description: "Marks the server as a backup server. It will be used when the primary servers are unavailable. Cannot be used in combination with \"Preserve client IP on the same upstream\".",
						},
						"down": {
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     false,
							Description: "Marks the server as unavailable.",
						},
						"fail_timeout": {
							Type:        schema.TypeString,
							Optional:    true,
							Default:     "1",
							Description: "Double usage: 1. Time period in which the max_fails must occur until the upstream is deactivated. 2. Time period the upstream is deactivated until it is reactivated. The time during which the specified number of unsuccessful attempts \"Max fails\" to communicate with the server should happen to consider the server unavailable. Also the period of time the server will be considered unavailable. Default is 10 seconds.",
						},
						"max_fails": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     100,
							Description: "The number of unsuccessful attempts to communicate with the server that should happen in the duration set by \"Fail timeout\" to consider the server unavailable. Also the server is considered unavailable for the duration set by \"Fail timeout\". By default, the number of unsuccessful attempts is set to 1. Setting the value to zero disables the accounting of attempts. What is considered an unsuccessful attempt is defined by the \"Next upstream error handling\".",
						},
						"weight": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     1,
							Description: "Weight defines the count of requests a upstream handles before the next upstream is selected.",
						},
					},
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
		CustomizeDiff: checkRecordTypeAndReversedDomain,
	}
}

func checkRecordTypeAndReversedDomain(ctx context.Context, d *schema.ResourceDiff, meta interface{}) error {

	domainName := d.Get("domain_name").(string)
	recordType := d.Get("record_type").(string)

	domain, _ := findDomainByDomainName(meta, domainName)
	if domain == nil {
		return nil
	}

	value := d.Get("value").(string)
	err := validateIpAddress(recordType, value)
	if err != nil {
		return err
	}
	err = validateNonIpAddress(recordType, value)
	if err != nil {
		return err
	}
	err = validateMxValue(recordType, value)
	if err != nil {
		return err
	}

	if (!domain.Reversed && recordType == "PTR") || (domain.Reversed && recordType != "PTR") {
		return fmt.Errorf("PTR records are possible only for reversed domains. Reversed domains can only have PTR records")
	}

	return nil
}

func validateIpAddress(recordType string, ip string) error {
	if recordType != "A" && recordType != "AAAA" {
		return nil
	}

	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return fmt.Errorf("%s is not a valid ip address", ip)
	}

	if recordType == "A" && ipAddress.To4() == nil {
		return fmt.Errorf("%s is not a valid IPv4 address", ip)
	}

	if recordType == "AAAA" && ipAddress.To4() != nil {
		return fmt.Errorf("%s is not a valid IPv6 address", ip)
	}

	return nil
}

func validateNonIpAddress(recordType string, value string) error {
	if recordType != "NS" && recordType != "CNAME" {
		return nil
	}

	ip := net.ParseIP(value)
	if ip != nil {
		return fmt.Errorf("%s looks like an ip address, which is not allowed here", value)
	}

	return nil
}

func validateMxValue(recordType string, value string) error {
	if recordType != "MX" {
		return nil
	}

	m, err := regexp.Match(`^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])*\.?$`, []byte(value))
	if err != nil {
		return err
	}
	if !m {
		return fmt.Errorf("%s is not a valid value for this DNS record type %s", value, recordType)
	}

	return nil
}

// resourceMyrasecDNSRecordCreate ...
func resourceMyrasecDNSRecordCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	record, err := buildDNSRecord(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building DNS record",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	resp, err := client.CreateDNSRecord(record, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating DNS record",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecDNSRecordRead(ctx, d, meta)
}

// resourceMyrasecDNSRecordRead ...
func resourceMyrasecDNSRecordRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("domain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[domain_name] is not set")),
		})
		return diags
	}

	domainName := name.(string)
	recordID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing DNS record ID",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	record, diags := findDNSRecord(recordID, meta, domainID)
	if diags.HasError() {
		return diags
	}

	if record == nil {
		d.SetId("")
		return nil
	}

	setDNSRecordData(d, record, domainName, domainID)

	return diags
}

// resourceMyrasecDNSRecordUpdate ...
func resourceMyrasecDNSRecordUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	recordID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing record id",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating DNS record: %v", recordID)

	record, err := buildDNSRecord(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building DNS record",
			Detail:   formatError(err),
		})
		return diags
	}

	name, ok := d.GetOk("domain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[domain_name] is not set")),
		})
		return diags
	}

	domainName := name.(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	record, err = client.UpdateDNSRecord(record, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating DNS record",
			Detail:   formatError(err),
		})
		return diags
	}

	setDNSRecordData(d, record, domainName, domainID)

	return diags
}

// resourceMyrasecDNSRecordDelete ...
func resourceMyrasecDNSRecordDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	recordID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing record id",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting DNS record: %v", recordID)

	record, err := buildDNSRecord(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building DNS record",
			Detail:   formatError(err),
		})
		return diags
	}

	name, ok := d.GetOk("domain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[domain_name] is not set")),
		})
		return diags
	}

	domainName := name.(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	_, err = client.DeleteDNSRecord(record, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting DNS record",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecDNSRecordImport ...
func resourceMyrasecDNSRecordImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	domainName, recordID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing DNS record ID: [%s]", err.Error())
	}

	domainID, diags := findDomainIDByDomainName(d, meta, domainName)
	if diags.HasError() {
		return nil, fmt.Errorf("unable to find domainID by domainName: [%s]", domainName)
	}

	record, diags := findDNSRecord(recordID, meta, domainID)
	if diags.HasError() || record == nil {
		return nil, fmt.Errorf("unable to find DNS record for domain [%s] with ID = [%d]", domainName, recordID)
	}

	d.SetId(strconv.Itoa(recordID))
	d.Set("record_id", record.ID)
	d.Set("domain_name", domainName)

	resourceMyrasecDNSRecordRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildDNSRecord ...
func buildDNSRecord(d *schema.ResourceData, meta interface{}) (*myrasec.DNSRecord, error) {
	record := &myrasec.DNSRecord{
		Name:                 d.Get("name").(string),
		Value:                d.Get("value").(string),
		RecordType:           d.Get("record_type").(string),
		TTL:                  d.Get("ttl").(int),
		AlternativeCNAME:     d.Get("alternative_cname").(string),
		Active:               d.Get("active").(bool),
		Enabled:              d.Get("enabled").(bool),
		Priority:             d.Get("priority").(int),
		Port:                 d.Get("port").(int),
		Comment:              d.Get("comment").(string),
		Weight:               d.Get("weight").(int),
		CAATag:               d.Get("caa_tag").(string),
		CAAFlags:             d.Get("caa_flags").(int),
		Encryption:           d.Get("encryption").(int),
		HashType:             d.Get("hash_type").(int),
		IdentificationNumber: d.Get("identificationnumber").(int),
	}

	if d.Get("record_id").(int) > 0 {
		record.ID = d.Get("record_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			record.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	record.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	record.Modified = modified

	options, ok := d.GetOk("upstream_options")
	if !ok {
		return record, nil
	}

	for _, upstream := range options.([]interface{}) {
		opts, err := buildUpstreamOptions(upstream)
		if err != nil {
			return nil, err
		}

		record.UpstreamOptions = opts
	}

	return record, nil
}

// buildUpstreamOptions ...
func buildUpstreamOptions(upstream interface{}) (*myrasec.UpstreamOptions, error) {
	options := &myrasec.UpstreamOptions{}

	for key, val := range upstream.(map[string]interface{}) {
		switch key {
		case "upstream_id":
			options.ID = val.(int)
		case "modified":
			modified, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			options.Modified = modified
		case "created":
			created, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			options.Created = created
		case "backup":
			options.Backup = val.(bool)
		case "down":
			options.Down = val.(bool)
		case "fail_timeout":
			options.FailTimeout = val.(string)
		case "max_fails":
			options.MaxFails = val.(int)
		case "weight":
			options.Weight = val.(int)
		}
	}

	return options, nil
}

// findDNSRecord ...
func findDNSRecord(recordID int, meta interface{}, domainID int) (*myrasec.DNSRecord, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	r, err := client.GetDNSRecord(domainID, recordID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error loading DNS record",
			Detail:   formatError(err),
		})
		return nil, diags
	}
	if r != nil {
		return r, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find DNS record",
		Detail:   fmt.Sprintf("Unable to find DNS record with ID = [%d]", recordID),
	})
	return nil, diags
}

// setDNSRecordData ...
func setDNSRecordData(d *schema.ResourceData, record *myrasec.DNSRecord, domainName string, domainID int) {
	d.SetId(strconv.Itoa(record.ID))
	d.Set("record_id", record.ID)
	d.Set("name", record.Name)

	if record.RecordType == "PTR" {
		d.Set("value", myrasec.RemoveTrailingDot(record.Value))
	} else {
		d.Set("value", record.Value)
	}

	d.Set("record_type", record.RecordType)
	d.Set("ttl", record.TTL)
	d.Set("alternative_cname", record.AlternativeCNAME)
	d.Set("active", record.Active)
	d.Set("enabled", record.Enabled)
	d.Set("priority", record.Priority)
	d.Set("port", record.Port)
	d.Set("created", record.Created.Format(time.RFC3339))
	d.Set("modified", record.Modified.Format(time.RFC3339))
	d.Set("comment", record.Comment)
	d.Set("weight", record.Weight)
	d.Set("caa_tag", record.CAATag)
	d.Set("caa_flags", record.CAAFlags)
	d.Set("encryption", record.Encryption)
	d.Set("hash_type", record.HashType)
	d.Set("identificationnumber", record.IdentificationNumber)
	d.Set("domain_name", domainName)
	d.Set("domain_id", domainID)

	if record.UpstreamOptions != nil && record.UpstreamOptions.ID > 0 {
		d.Set("upstream_options", []map[string]interface{}{
			{
				"upstream_id":  record.UpstreamOptions.ID,
				"created":      record.UpstreamOptions.Created.Format(time.RFC3339),
				"modified":     record.UpstreamOptions.Modified.Format(time.RFC3339),
				"backup":       record.UpstreamOptions.Backup,
				"down":         record.UpstreamOptions.Down,
				"fail_timeout": record.UpstreamOptions.FailTimeout,
				"max_fails":    record.UpstreamOptions.MaxFails,
				"weight":       record.UpstreamOptions.Weight,
			},
		})
	}
}
