package myrasec

import (
	"context"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// dataSourceMyrasecWaitingRooms ...
func dataSourceMyrasecWaitingRooms() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecWaitingRoomsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"subdomain_name": {
							Type:     schema.TypeString,
							Required: false,
							Optional: true,
						},
						"domain_id": {
							Type:     schema.TypeInt,
							Required: false,
							Optional: true,
						},
					},
				},
			},
			"waitingrooms": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"subdomain_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"waitingroom_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"vhost_id": {
							Type:     schema.TypeInt,
							Optional: true,
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
						"paths": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"max_concurrent": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"session_timeout": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"wait_refresh": {
							Type:     schema.TypeInt,
							Computed: true,
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

// dataSourceMyrasecWaitingRoomsRead ...
func dataSourceMyrasecWaitingRoomsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var limits []myrasec.WaitingRoom
	var diags diag.Diagnostics
	f := prepareWaitingroomFilter(d.Get("filter"))
	if f == nil {
		f = &waitingRoomFilter{}
	}

	params := map[string]string{}

	if f.subDomainName != "" {
		limits, diags = listWaitingRoomsForSubDomain(meta, f.subDomainName, params)
		if diags.HasError() {
			return diags
		}

	} else if f.domainId != 0 {
		limits, diags = listWaitingRoomsForDomain(meta, f.domainId, params)
		if diags.HasError() {
			return diags
		}
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching waiting rooms",
			Detail:   "No parameter passed, either a subdomain_name or domain_id must be present",
		})
		return diags
	}

	waitingRoomData := make([]interface{}, 0)
	for _, r := range limits {
		waitingRoomData = append(waitingRoomData, map[string]interface{}{
			"waitingroom_id":  r.ID,
			"created":         r.Created.Format(time.RFC3339),
			"modified":        r.Modified.Format(time.RFC3339),
			"subdomain_name":  r.SubDomainName,
			"name":            r.Name,
			"vhost_id":        r.VhostId,
			"max_concurrent":  r.MaxConcurrent,
			"session_timeout": r.SessionTimeout,
			"wait_refresh":    r.WaitRefresh,
			"paths":           r.Paths,
		})
	}

	if err := d.Set("waitingrooms", waitingRoomData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

// prepareWaitingroomFilter fetches the panic that can happen in parseWaitingroomFilter
func prepareWaitingroomFilter(d interface{}) *waitingRoomFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareWaitingroomFilter", r)
		}
	}()

	return parseWaitingRoomFilter(d)
}

// parseWaitingRoomFilter converts the filter data to a waitingroomFilter struct
func parseWaitingRoomFilter(d interface{}) *waitingRoomFilter {
	cfg := d.([]interface{})
	f := &waitingRoomFilter{}

	m := cfg[0].(map[string]interface{})

	subDomainName, ok := m["subdomain_name"]
	if ok {
		f.subDomainName = subDomainName.(string)
	}

	domainId, ok := m["domain_id"]
	if ok {
		f.domainId = domainId.(int)
	}

	return f
}

// listWaitingRoomsForSubDomain ...
func listWaitingRoomsForSubDomain(meta interface{}, subDomainName string, params map[string]string) ([]myrasec.WaitingRoom, diag.Diagnostics) {
	var diags diag.Diagnostics
	var limits []myrasec.WaitingRoom
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListWaitingRoomsForSubDomain(subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching waiting rooms",
				Detail:   formatError(err),
			})
			return limits, diags
		}
		limits = append(limits, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return limits, diags
}

// listWaitingRoomsForDomain ...
func listWaitingRoomsForDomain(meta interface{}, domainId int, params map[string]string) ([]myrasec.WaitingRoom, diag.Diagnostics) {
	var diags diag.Diagnostics
	var limits []myrasec.WaitingRoom
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListWaitingRoomsForDomain(domainId, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching waiting rooms",
				Detail:   formatError(err),
			})
			return limits, diags
		}
		limits = append(limits, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return limits, diags
}

// waitingRoomFilter struct ...
type waitingRoomFilter struct {
	subDomainName string
	domainId      int
}
