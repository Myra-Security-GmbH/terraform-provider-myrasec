package myrasec

// myrasec "github.com/Myra-Security-GmbH/myrasec-go"

import (
	"context"
	"log"
	"regexp"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceMyrasecDNSRecords ...
//
func dataSourceMyrasecDNSRecords() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecDNSRecordsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain_name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"match": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"records": {
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

						"ttl": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"record_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"alternative_cname": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"active": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"comment": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"priority": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"port": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"upstream_options": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"upstream_id": {
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
									"backup": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"down": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"fail_timeout": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"max_fails": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"weight": {
										Type:     schema.TypeInt,
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
// dataSourceMyrasecDNSRecordsRead ...
//
func dataSourceMyrasecDNSRecordsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareDNSRecordFilter(d.Get("filter"))
	if f == nil {
		f = &recordFilter{}
	}

	params := map[string]string{
		"loadbalancer": "true",
	}

	if f.regex == nil && len(f.name) > 0 {
		params["search"] = f.name
	}

	records, diags := listDnsRecords(meta, f.domainName, params)
	if diags.HasError() {
		return diags
	}

	recordData := make([]interface{}, 0)

	for _, r := range records {

		if f.regex != nil && !f.regex.MatchString(r.Name) {
			continue
		}

		var created string
		if r.Created != nil {
			created = r.Created.Format(time.RFC3339)
		}

		var modified string
		if r.Created != nil {
			modified = r.Modified.Format(time.RFC3339)
		}

		data := map[string]interface{}{
			"id":                r.ID,
			"created":           created,
			"modified":          modified,
			"name":              r.Name,
			"record_type":       r.RecordType,
			"value":             r.Value,
			"ttl":               r.TTL,
			"alternative_cname": r.AlternativeCNAME,
			"active":            r.Active,
			"enabled":           r.Enabled,
			"priority":          r.Priority,
			"port":              r.Port,
			"comment":           r.Comment,
		}

		if r.UpstreamOptions != nil && r.UpstreamOptions.ID != 0 {

			var upstreamCreated string
			if r.Created != nil {
				upstreamCreated = r.UpstreamOptions.Created.Format(time.RFC3339)
			}

			var upstreamModified string
			if r.Created != nil {
				upstreamModified = r.UpstreamOptions.Modified.Format(time.RFC3339)
			}

			data["upstream_options"] = []map[string]interface{}{
				{
					"upstream_id":  r.UpstreamOptions.ID,
					"created":      upstreamCreated,
					"modified":     upstreamModified,
					"backup":       r.UpstreamOptions.Backup,
					"down":         r.UpstreamOptions.Down,
					"fail_timeout": r.UpstreamOptions.FailTimeout,
					"max_fails":    r.UpstreamOptions.MaxFails,
					"weight":       r.UpstreamOptions.Weight,
				},
			}
		}

		recordData = append(recordData, data)
	}

	if err := d.Set("records", recordData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

//
// prepareDNSRecordFilter fetches the panic that can happen in parseDNSRecordFilter
//
func prepareDNSRecordFilter(d interface{}) *recordFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareDNSRecordFilter", r)
		}
	}()

	return parseDNSRecordFilter(d)
}

//
// parseDNSRecordFilter converts the filter data to a recordFilter struct
//
func parseDNSRecordFilter(d interface{}) *recordFilter {
	cfg := d.([]interface{})
	f := &recordFilter{}

	m := cfg[0].(map[string]interface{})

	domainName, ok := m["domain_name"]
	if ok {
		f.domainName = domainName.(string)
	}

	name, ok := m["name"]
	if ok {
		f.name = name.(string)
	}

	match, ok := m["match"]
	if ok {
		regex, err := regexp.Compile(match.(string))
		if err != nil {
			log.Println("[WARN] The passed regex is not valid", err.Error())

			return f
		}
		f.regex = regex
	}

	return f
}

//
// listDnsRecords ...
//
func listDnsRecords(meta interface{}, domainName string, params map[string]string) ([]myrasec.DNSRecord, diag.Diagnostics) {
	var diags diag.Diagnostics
	var records []myrasec.DNSRecord

	client := meta.(*myrasec.API)

	params["pageSize"] = "50"
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListDNSRecords(domainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching DNS records",
				Detail:   err.Error(),
			})
			return records, diags
		}
		records = append(records, res...)
		if len(res) < 50 {
			break
		}
		page++
	}

	return records, diags
}

//
// recordFilter struct ...
//
type recordFilter struct {
	domainName string
	name       string
	regex      *regexp.Regexp
}
