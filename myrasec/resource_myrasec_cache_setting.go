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
// resourceMyrasecCacheSetting ...
//
func resourceMyrasecCacheSetting() *schema.Resource {
	return &schema.Resource{
		Create: resourceMyrasecCacheSettingCreate,
		Read:   resourceMyrasecCacheSettingRead,
		Delete: resourceMyrasecCacheSettingDelete,

		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{
			"subdomain_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				StateFunc: func(i interface{}) string {
					return strings.ToLower(i.(string))
				},
				Description: "The Subdomain for the cache Setting.",
			},
			"setting_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the cache setting.",
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
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"exact", "prefix", "suffix"}, false),
				Description:  "Type how path should match.",
			},
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path which must match to cache response.",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Required:    true,
				ForceNew:    true,
				Description: "Time to live.",
			},
			"not_found_ttl": {
				Type:        schema.TypeInt,
				Required:    true,
				ForceNew:    true,
				Description: "How long an object will be cached. Origin responses with the HTTP codes 404 will be cached.",
			},
			"sort": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Default:     0,
				Description: "The order in which the cache rules take action as long as the cache sorting is activated.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Define wether this cache setting is enabled or not.",
			},
			"enforce": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "Enforce cache TTL allows you to set the cache TTL (Cache Control: max-age) in the backend regardless of the response sent from your Origin.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecCacheSettingCreate ...
//
func resourceMyrasecCacheSettingCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	setting, err := buildCacheSetting(d, meta)
	if err != nil {
		return fmt.Errorf("Error building cache setting: %s", err)
	}

	resp, err := client.CreateCacheSetting(setting, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error creating cache setting: %s", err)
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecCacheSettingRead(d, meta)
}

//
// resourceMyrasecCacheSettingRead ...
//
func resourceMyrasecCacheSettingRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing setting id: %s", err)
	}

	settings, err := client.ListCacheSettings(d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error fetching cache settings: %s", err)
	}

	for _, s := range settings {
		if s.ID != settingID {
			continue
		}
		d.Set("setting_id", s.ID)
		d.Set("created", s.Created)
		d.Set("modified", s.Modified)
		d.Set("type", s.Type)
		d.Set("path", s.Path)
		d.Set("ttl", s.TTL)
		d.Set("not_found_ttl", s.NotFoundTTL)
		d.Set("sort", s.Sort)
		d.Set("enabled", s.Enabled)
		d.Set("enforce", s.Enforce)
		break
	}

	return nil
}

//
// resourceMyrasecCacheSettingDelete ...
//
func resourceMyrasecCacheSettingDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*myrasec.API)

	settingID, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Error parsing setting id: %s", err)
	}

	log.Printf("[INFO] Deleting cache setting: %v", settingID)

	setting, err := buildCacheSetting(d, meta)
	if err != nil {
		return fmt.Errorf("Error building cache setting: %s", err)
	}

	_, err = client.DeleteCacheSetting(setting, d.Get("subdomain_name").(string))
	if err != nil {
		return fmt.Errorf("Error deleting cache setting: %s", err)
	}
	return err
}

//
// buildCacheSetting ...
//
func buildCacheSetting(d *schema.ResourceData, meta interface{}) (*myrasec.CacheSetting, error) {
	setting := &myrasec.CacheSetting{
		Type:        d.Get("type").(string),
		Path:        d.Get("path").(string),
		TTL:         d.Get("ttl").(int),
		NotFoundTTL: d.Get("not_found_ttl").(int),
		Sort:        d.Get("sort").(int),
		Enabled:     d.Get("enabled").(bool),
		Enforce:     d.Get("enforce").(bool),
	}

	if d.Get("setting_id").(int) > 0 {
		setting.ID = d.Get("setting_id").(int)
	}

	if len(d.Get("created").(string)) > 0 {
		created, err := time.Parse(time.RFC3339, d.Get("created").(string))

		if err != nil {
			return nil, err
		}

		setting.Created = &types.DateTime{
			Time: created,
		}
	}

	if len(d.Get("modified").(string)) > 0 {
		modified, err := time.Parse(time.RFC3339, d.Get("modified").(string))

		if err != nil {
			return nil, err
		}
		setting.Modified = &types.DateTime{
			Time: modified,
		}
	}

	return setting, nil
}
