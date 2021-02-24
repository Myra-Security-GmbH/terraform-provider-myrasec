package myrasec

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/Myra-Security-GmbH/myrasec-go/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

//
// resourceMyrasecDomain ...
//
func resourceMyrasecDomain() *schema.Resource {
	return &schema.Resource{
		Create: resourceMyrasecDomainCreate,
		Read:   resourceMyrasecDomainRead,
		Update: resourceMyrasecDomainUpdate,
		Delete: resourceMyrasecDomainDelete,

		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the domain.",
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
				Description: "Domain name.",
			},
			"auto_update": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Auto update flag for the domain.",
			},
			"auto_dns": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Auto DNS flag for the domain.",
			},
			"paused": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Shows if Myra is paused for this domain.",
			},
			"paused_until": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Date until Myra will be automatically reactivated.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecDomainCreate ...
//
func resourceMyrasecDomainCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	domain, err := buildDomain(d, meta)
	if err != nil {
		return fmt.Errorf("Error building domain: %s", err)
	}

	resp, err := client.CreateDomain(domain)
	if err != nil {
		return fmt.Errorf("Error creating domain: %s", err)
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecDomainRead(d, meta)
}

//
// resourceMyrasecDomainRead ...
//
func resourceMyrasecDomainRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	domainID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing domain id: %s", err)
	}

	domains, err := client.ListDomains(nil)
	if err != nil {
		return fmt.Errorf("Error fetching domains: %s", err)
	}

	for _, r := range domains {
		if r.ID != domainID {
			continue
		}
		d.Set("domain_id", r.ID)
		d.Set("name", r.Name)
		d.Set("auto_update", r.AutoUpdate)
		d.Set("auto_dns", r.AutoDNS)
		d.Set("paused", r.Paused)
		d.Set("paused_until", r.PausedUntil)
		d.Set("created", r.Created.Format(time.RFC3339))
		d.Set("modified", r.Modified.Format(time.RFC3339))
		break
	}

	return nil
}

//
// resourceMyrasecDomainUpdate ...
//
func resourceMyrasecDomainUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	domain, err := buildDomain(d, meta)
	if err != nil {
		return fmt.Errorf("Error building domain: %s", err)
	}

	resp, err := client.UpdateDomain(domain)
	if err != nil {
		return fmt.Errorf("Error updating domain: %s", err)
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecDomainRead(d, meta)
}

//
// resourceMyrasecDomainDelete ...
//
func resourceMyrasecDomainDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	domainID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing domain id: %s", err)
	}

	log.Printf("[INFO] Deleting Domain: %v", domainID)

	domain, err := buildDomain(d, meta)
	if err != nil {
		return fmt.Errorf("Error building domain: %s", err)
	}

	_, err = client.DeleteDomain(domain)
	if err != nil {
		return fmt.Errorf("Error deleting domain: %s", err)
	}
	return err
}

//
// buildDomain ...
//
func buildDomain(d *schema.ResourceData, meta interface{}) (*myrasec.Domain, error) {
	domain := &myrasec.Domain{
		Name:       d.Get("name").(string),
		AutoUpdate: d.Get("auto_update").(bool),
		AutoDNS:    d.Get("auto_dns").(bool),
		Paused:     d.Get("paused").(bool),
	}

	if d.Get("domain_id").(int) > 0 {
		domain.ID = d.Get("domain_id").(int)
	}

	if len(d.Get("created").(string)) > 0 {
		created, err := time.Parse(time.RFC3339, d.Get("created").(string))
		if err != nil {
			return nil, err
		}

		domain.Created = &types.DateTime{
			Time: created,
		}
	}

	if len(d.Get("modified").(string)) > 0 {
		modified, err := time.Parse(time.RFC3339, d.Get("modified").(string))
		if err != nil {
			return nil, err
		}

		domain.Modified = &types.DateTime{
			Time: modified,
		}
	}

	if len(d.Get("paused_until").(string)) > 0 {
		pausedUntil, err := time.Parse(time.RFC3339, d.Get("paused_until").(string))
		if err != nil {
			return nil, err
		}

		domain.PausedUntil = &types.DateTime{
			Time: pausedUntil,
		}
	}

	return domain, nil
}
