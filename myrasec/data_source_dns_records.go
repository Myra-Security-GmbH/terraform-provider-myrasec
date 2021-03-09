package myrasec

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceMyrasecDNSRecords ...
//
func dataSourceMyrasecDNSRecords() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceMyrasecDNSRecordsRead,
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
	}
}

//
// dataSourceMyrasecDNSRecordsRead ...
//
func dataSourceMyrasecDNSRecordsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	f := parseDNSRecordFilter(d.Get("filter"))

	params := map[string]string{
		"loadbalancer": "true",
	}

	if f.regex == nil && len(f.name) > 0 {
		params["search"] = f.name
	}

	records, err := client.ListDNSRecords(f.domainName, params)
	if err != nil {
		return fmt.Errorf("Error fetching DNS records: %s", err)
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
		return err
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
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
		f.regex = regexp.MustCompile(match.(string))
	}
	return f
}

//
// recordFilter struct ...
//
type recordFilter struct {
	domainName string
	name       string
	regex      *regexp.Regexp
}