package myrasec

import (
	"fmt"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// dataSourceDNSRecords ...
//
func dataSourceDNSRecords() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceDNSRecordsRead,
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
// dataSourceDNSRecordsRead ...
//
func dataSourceDNSRecordsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	f := parseDNSRecordFilter(d.Get("filter"))

	params := map[string]string{
		"loadbalancer": "true",
	}
	if len(f.name) > 0 {
		params["search"] = f.name
	}

	records, err := client.ListDNSRecords(f.domainName, params)
	if err != nil {
		return fmt.Errorf("Error fetching DNS records: %s", err)
	}

	recordData := make([]interface{}, 0)
	for _, r := range records {
		created := r.Created.Format(time.RFC3339)
		modified := r.Modified.Format(time.RFC3339)

		upstreamCreated := r.Created.Format(time.RFC3339)
		upstreamModified := r.Modified.Format(time.RFC3339)
		recordData = append(recordData, map[string]interface{}{
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
			"upstream_options": map[string]interface{}{
				"upstream_id":  r.UpstreamOptions.ID,
				"created":      upstreamCreated,
				"modified":     upstreamModified,
				"backup":       r.UpstreamOptions.Backup,
				"down":         r.UpstreamOptions.Down,
				"fail_timeout": r.UpstreamOptions.FailTimeout,
				"max_fails":    r.UpstreamOptions.MaxFails,
				"weight":       r.UpstreamOptions.Weight,
			},
		})
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

	return f
}

//
// recordFilter struct ...
//
type recordFilter struct {
	domainName string
	name       string
}
