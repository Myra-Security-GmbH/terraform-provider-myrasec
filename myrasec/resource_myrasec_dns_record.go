package myrasec

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/Myra-Security-GmbH/myrasec-go/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

//
// resourceMyrasecDNSRecord ...
//
func resourceMyrasecDNSRecord() *schema.Resource {
	return &schema.Resource{
		Create: resourceMyrasecDNSRecordCreate,
		Read:   resourceMyrasecDNSRecordRead,
		Delete: resourceMyrasecDNSRecordDelete,

		SchemaVersion: 1,
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
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "Subdomain name of a DNS record.",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Required:    true,
				ForceNew:    true,
				Description: "Time to live.",
			},
			"record_type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"A", "AAAA", "MX", "CNAME", "TXT", "NS", "SRV", "CAA"}, false),
				Description:  "A record type to identify the type of a record. Valid types are: A, AAAA, MX, CNAME, TXT, NS, SRV and CAA.",
			},
			"alternative_cname": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The alternative CNAME that points to the record.",
			},
			"active": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Define wether this subdomain should be protected by Myra or not.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Define wether this DNS record is enabled or not.",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				ForceNew:    true,
				Description: "A comment to describe this DNS record.",
			},
			"value": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Depends on the record type. Typically an IPv4/6 address or a domain entry.",
			},
			"priority": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "Priority of MX records.",
			},
			"port": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "Port for SRV records.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecDNSRecordCreate ...
//
func resourceMyrasecDNSRecordCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	record, err := buildDNSRecord(d, meta)
	if err != nil {
		return fmt.Errorf("Error building DNS record: %s", err)
	}

	resp, err := client.CreateDNSRecord(record, d.Get("domain_name").(string))
	if err != nil {
		return fmt.Errorf("Error creating DNS record: %s", err)
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecDNSRecordRead(d, meta)
}

//
// resourceMyrasecDNSRecordRead ...
//
func resourceMyrasecDNSRecordRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	recordID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing record id: %s", err)
	}

	records, err := client.ListDNSRecords(d.Get("domain_name").(string))
	if err != nil {
		return fmt.Errorf("Error fetching DNS records: %s", err)
	}

	for _, r := range records {
		if r.ID != recordID {
			continue
		}
		d.Set("record_id", r.ID)
		d.Set("name", r.Name)
		d.Set("value", r.Value)
		d.Set("record_type", r.RecordType)
		d.Set("ttl", r.TTL)
		d.Set("alternative_cname", r.AlternativeCNAME)
		d.Set("active", r.Active)
		d.Set("enabled", r.Enabled)
		d.Set("priority", r.Priority)
		d.Set("port", r.Port)
		d.Set("created", r.Created)
		d.Set("modified", r.Modified)
		d.Set("comment", r.Comment)
		break
	}

	return nil
}

//
// resourceMyrasecDNSRecordDelete ...
//
func resourceMyrasecDNSRecordDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	recordID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing record id: %s", err)
	}

	log.Printf("[INFO] Deleting DNS record: %v", recordID)

	record, err := buildDNSRecord(d, meta)
	if err != nil {
		return fmt.Errorf("Error building DNS record: %s", err)
	}

	_, err = client.DeleteDNSRecord(record, d.Get("domain_name").(string))
	if err != nil {
		return fmt.Errorf("Error deleting DNS record: %s", err)
	}
	return nil
}

//
// buildDNSRecord ...
//
func buildDNSRecord(d *schema.ResourceData, meta interface{}) (*myrasec.DNSRecord, error) {
	record := &myrasec.DNSRecord{
		Name:             d.Get("name").(string),
		Value:            d.Get("value").(string),
		RecordType:       d.Get("record_type").(string),
		TTL:              d.Get("ttl").(int),
		AlternativeCNAME: d.Get("alternative_cname").(string),
		Active:           d.Get("active").(bool),
		Enabled:          d.Get("enabled").(bool),
		Priority:         d.Get("priority").(int),
		Port:             d.Get("port").(int),
		Comment:          d.Get("comment").(string),
	}

	if d.Get("record_id").(int) > 0 {
		record.ID = d.Get("record_id").(int)
	}

	if len(d.Get("created").(string)) > 0 {
		created, err := time.Parse(time.RFC3339, d.Get("created").(string))

		if err != nil {
			return nil, err
		}

		record.Created = &types.DateTime{
			Time: created,
		}
	}

	if len(d.Get("modified").(string)) > 0 {
		modified, err := time.Parse(time.RFC3339, d.Get("modified").(string))

		if err != nil {
			return nil, err
		}
		record.Modified = &types.DateTime{
			Time: modified,
		}
	}

	return record, nil
}
