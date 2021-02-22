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
// resourceMyrasecRedirect ...
//
func resourceMyrasecRedirect() *schema.Resource {
	return &schema.Resource{
		Create: resourceMyrasecRedirectCreate,
		Read:   resourceMyrasecRedirectRead,
		Delete: resourceMyrasecRedirectDelete,

		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{
			"redirect_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the redirect.",
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
			"matching_type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"exact", "prefix", "suffix"}, false),
				Description:  "Type to match the redirect.",
			},
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the redirect.",
			},
			"source": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Location to match against.",
			},
			"destination": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Target where redirect should point to.",
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"permanent", "redirect"}, false),
				Description:  "Type of redirection.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Define wether this redirect is enabled or not.",
			},
			"sort": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Default:     0,
				Description: "The ascending order for the redirect rules.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecRedirectCreate ...
//
func resourceMyrasecRedirectCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	redirect, err := buildRedirect(d, meta)
	if err != nil {
		return fmt.Errorf("Error building redirect: %s", err)
	}

	resp, err := client.CreateRedirect(redirect, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error creating redirect: %s", err)
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecRedirectRead(d, meta)
}

//
// resourceMyrasecRedirectRead ...
//
func resourceMyrasecRedirectRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	redirectID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing redirect id: %s", err)
	}

	redirects, err := client.ListRedirects(d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error fetching redirects: %s", err)
	}

	for _, r := range redirects {
		if r.ID != redirectID {
			continue
		}
		d.Set("redirect_id", r.ID)
		d.Set("created", r.Created)
		d.Set("modified", r.Modified)
		d.Set("type", r.Type)
		d.Set("subdomain_name", r.SubDomainName)
		d.Set("source", r.Source)
		d.Set("destination", r.Destination)
		d.Set("sort", r.Sort)
		d.Set("matching_type", r.MatchingType)
		d.Set("enabled", r.Enabled)
		break
	}

	return nil
}

//
// resourceMyrasecRedirectDelete ...
//
func resourceMyrasecRedirectDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	redirectID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing redirect id: %s", err)
	}

	log.Printf("[INFO] Deleting redirect: %v", redirectID)

	redirect, err := buildRedirect(d, meta)
	if err != nil {
		return fmt.Errorf("Error building redirect: %s", err)
	}

	_, err = client.DeleteRedirect(redirect, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error deleting redirect: %s", err)
	}
	return err
}

//
// buildRedirect ...
//
func buildRedirect(d *schema.ResourceData, meta interface{}) (*myrasec.Redirect, error) {
	redirect := &myrasec.Redirect{
		Type:          d.Get("type").(string),
		MatchingType:  d.Get("matching_type").(string),
		SubDomainName: d.Get("subdomain_name").(string),
		Source:        d.Get("source").(string),
		Destination:   d.Get("destination").(string),
		Sort:          d.Get("sort").(int),
		Enabled:       d.Get("enabled").(bool),
	}

	if d.Get("redirect_id").(int) > 0 {
		redirect.ID = d.Get("redirect_id").(int)
	}

	if len(d.Get("created").(string)) > 0 {
		created, err := time.Parse("2006-01-02T15:04:05-0700", d.Get("created").(string))
		if err != nil {
			return nil, err
		}

		redirect.Created = &types.DateTime{
			Time: created,
		}
	}

	if len(d.Get("modified").(string)) > 0 {
		modified, err := time.Parse("2006-01-02T15:04:05-0700", d.Get("modified").(string))
		if err != nil {
			return nil, err
		}
		redirect.Modified = &types.DateTime{
			Time: modified,
		}
	}

	return redirect, nil
}
