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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

//
// resourceMyrasecRateLimit ...
//
func resourceMyrasecRateLimit() *schema.Resource {
	return &schema.Resource{
		Create: resourceMyrasecRateLimitCreate,
		Read:   resourceMyrasecRateLimitRead,
		Delete: resourceMyrasecRateLimitDelete,

		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the rate limit setting.",
			},
			"ratelimit_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the rate limit setting.",
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
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Type of the rate limit setting.",
			},
			"network": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "Network in CIDR notation affected by the rate limiter.",
			},
			"value": {
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.IntInSlice([]int{4000, 2000, 1000, 500, 100, 60, 0}),
				Default:      1000,
				Description:  "Maximum amount of requests for the given network.",
			},
			"burst": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Default:     50,
				Description: "Burst defines how many requests a client can make in excess of the specified rate.",
			},
			"timeframe": {
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.IntInSlice([]int{1, 2, 5, 10, 15, 30, 45, 60, 120, 180, 300, 600, 1200, 3600}),
				Default:      60,
				Description:  "The affected timeframe in seconds for the rate limit.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecRateLimitCreate ...
//
func resourceMyrasecRateLimitCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		return fmt.Errorf("Error building rate limit: %s", err)
	}

	resp, err := client.CreateRateLimit(ratelimit)
	if err != nil {
		return fmt.Errorf("Error creating rate limit setting: %s", err)
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecRateLimitRead(d, meta)
}

//
// resourceMyrasecRateLimitRead ...
//
func resourceMyrasecRateLimitRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	rateLimitID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing rate limit id: %s", err)
	}

	ratelimits, err := client.ListRateLimits(map[string]string{"subDomainName": d.Get("subdomain_name").(string)})
	if err != nil {
		return fmt.Errorf("Error fetching rate limit settings: %s", err)
	}

	for _, r := range ratelimits {
		if r.ID != rateLimitID {
			continue
		}
		d.Set("ratelimit_id", r.ID)
		d.Set("created", r.Created.Format(time.RFC3339))
		d.Set("modified", r.Modified.Format(time.RFC3339))
		d.Set("type", r.Type)
		d.Set("network", r.Network)
		d.Set("value", r.Value)
		d.Set("burst", r.Burst)
		d.Set("timeframe", r.Timeframe)
		d.Set("subdomain_name", r.SubDomainName)

		break
	}

	return nil
}

//
// resourceMyrasecRateLimitDelete ...
//
func resourceMyrasecRateLimitDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	rateLimitID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing rate limit id: %s", err)
	}

	log.Printf("[INFO] Deleting rate limit setting: %v", rateLimitID)

	ratelimit, err := buildRateLimit(d, meta)
	if err != nil {
		return fmt.Errorf("Error building rate limit: %s", err)
	}

	_, err = client.DeleteRateLimit(ratelimit)
	if err != nil {
		return fmt.Errorf("Error deleting rate limit setting: %s", err)
	}
	return err
}

//
// buildRateLimit ...
//
func buildRateLimit(d *schema.ResourceData, meta interface{}) (*myrasec.RateLimit, error) {
	ratelimit := &myrasec.RateLimit{
		Type:          d.Get("type").(string),
		Network:       d.Get("network").(string),
		SubDomainName: d.Get("subdomain_name").(string),
		Value:         d.Get("value").(int),
		Burst:         d.Get("burst").(int),
		Timeframe:     d.Get("timeframe").(int),
	}

	if d.Get("ratelimit_id").(int) > 0 {
		ratelimit.ID = d.Get("ratelimit_id").(int)
	}

	if len(d.Get("created").(string)) > 0 {
		created, err := time.Parse(time.RFC3339, d.Get("created").(string))
		if err != nil {
			return nil, err
		}

		ratelimit.Created = &types.DateTime{
			Time: created,
		}
	}

	if len(d.Get("modified").(string)) > 0 {
		modified, err := time.Parse(time.RFC3339, d.Get("modified").(string))
		if err != nil {
			return nil, err
		}
		ratelimit.Modified = &types.DateTime{
			Time: modified,
		}
	}

	return ratelimit, nil
}
