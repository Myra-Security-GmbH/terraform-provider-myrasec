package myrasec

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// resourceMyrasecWaitingRoom ...
func resourceMyrasecWaitingRoom() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecWaitingRoomCreate,
		ReadContext:   resourceMyrasecWaitingRoomRead,
		UpdateContext: resourceMyrasecWaitingRoomUpdate,
		DeleteContext: resourceMyrasecWaitingRoomDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecWaitingRoomImport,
		},
		Schema: map[string]*schema.Schema{
			"waitingroom_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the waiting room.",
			},
			"vhost_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the waiting room Vhost.",
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
			"subdomain_name": {
				Type:        schema.TypeString,
				Optional:    false,
				Required:    true,
				ForceNew:    true,
				Description: "The Subdomain for the waiting room.",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new)
				},
			},
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the waiting room.",
			},
			"content": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Content of the waiting room.",
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					oldHash := d.Get("content_hash")
					newHash := createContentHash(newValue)
					return oldHash == newHash
				},
			},
			"content_hash": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"paths": {
				Type:        schema.TypeSet,
				Optional:    false,
				Required:    true,
				Description: "Paths of the waiting room.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"max_concurrent": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1000,
				Description: "Maximum amount of concurrent requests.",
			},
			"session_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     50,
				Description: "Session timeout.",
			},
			"wait_refresh": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     60,
				Description: "The affected timeframe in seconds for the waiting room.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// Global lock to enforce sequential execution
var creationLock sync.Mutex

// resourceMyrasecWaitingRoomCreate ...
func resourceMyrasecWaitingRoomCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	waitingroom, err := buildWaitingRoom(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building waiting room setting",
			Detail:   formatError(err),
		})
		return diags
	}

	creationLock.Lock() // Ensure only one resource is created at a time
	defer creationLock.Unlock()

	time.Sleep(10 * time.Millisecond) // Delay between creations

	resp, err := client.CreateWaitingRoom(waitingroom)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating waiting room setting",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecWaitingRoomRead(ctx, d, meta)
}

// resourceMyrasecWaitingRoomRead ...
func resourceMyrasecWaitingRoomRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	waitingRoomID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing waiting room setting ID",
			Detail:   formatError(err),
		})
		return diags
	}

	waitingRoom, err := client.GetWaitingRoom(waitingRoomID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error fetching waiting room",
			Detail:   formatError(err),
		})
		return diags
	}

	setWaitingRoomData(d, waitingRoom)

	return diags
}

// resourceMyrasecWaitingRoomUpdate ...
func resourceMyrasecWaitingRoomUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	waitingRoomID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing waiting room ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating waiting room setting: %v", waitingRoomID)

	waitingroom, err := buildWaitingRoom(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building waiting room setting",
			Detail:   formatError(err),
		})
		return diags
	}

	creationLock.Lock() // Ensure only one resource is created at a time
	defer creationLock.Unlock()

	time.Sleep(10 * time.Millisecond) // Delay between creations

	waitingroom, err = client.UpdateWaitingRoom(waitingroom)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating waiting room setting",
			Detail:   formatError(err),
		})
		return diags
	}

	setWaitingRoomData(d, waitingroom)

	return diags
}

// resourceMyrasecWaitingRoomDelete ...
func resourceMyrasecWaitingRoomDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	waitingRoomID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing waiting room ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting waiting room setting: %v", waitingRoomID)

	waitingroom, err := buildWaitingRoom(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building waiting room setting",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.DeleteWaitingRoom(waitingroom)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting waiting room setting",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecWaitingRoomImport ...
func resourceMyrasecWaitingRoomImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {

	subDomainName, waitingRoomID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing waiting room ID: [%s]", err.Error())
	}

	waitingRoom, diags := findWaitingRoomForSubDomain(waitingRoomID, meta, subDomainName)
	if diags.HasError() || waitingRoom == nil {
		return nil, fmt.Errorf("unable to find waiting room for subdomain [%s] with ID = [%d]", subDomainName, waitingRoomID)
	}

	d.SetId(strconv.Itoa(waitingRoomID))
	d.Set("waitingroom_id", waitingRoom.ID)
	d.Set("subdomain_name", waitingRoom.SubDomainName)

	resourceMyrasecWaitingRoomRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildWaitingRoom ...
func buildWaitingRoom(d *schema.ResourceData, meta any) (*myrasec.WaitingRoom, error) {

	waitingroom := &myrasec.WaitingRoom{
		Name:           d.Get("name").(string),
		SubDomainName:  d.Get("subdomain_name").(string),
		VhostId:        d.Get("vhost_id").(int),
		MaxConcurrent:  d.Get("max_concurrent").(int),
		SessionTimeout: d.Get("session_timeout").(int),
		WaitRefresh:    d.Get("wait_refresh").(int),
		Content:        d.Get("content").(string),
	}

	if waitingroom.VhostId == 0 {
		client := meta.(*myrasec.API)

		params := map[string]string{
			"search":     waitingroom.SubDomainName,
			"filterType": "exact",
		}

		vhosts, err := client.ListAllSubdomains(params)
		if err != nil {
			return nil, errors.New("error fetching vhosts")
		}

		if len(vhosts) == 1 {
			waitingroom.VhostId = vhosts[0].ID
		} else {
			return nil, errors.New("expected exactly one vhost, but got a different number")
		}
	}

	rawPaths := d.Get("paths").(*schema.Set)
	for _, sd := range rawPaths.List() {
		waitingroom.Paths = append(waitingroom.Paths, sd.(string))
	}

	if d.Get("waitingroom_id").(int) > 0 {
		waitingroom.ID = d.Get("waitingroom_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			waitingroom.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	waitingroom.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	waitingroom.Modified = modified

	return waitingroom, nil
}

// findWaitingRoomForSubDomain ...
func findWaitingRoomForSubDomain(waitingRoomID int, meta any, subDomainName string) (*myrasec.WaitingRoom, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	pageSize := 250
	params := map[string]string{
		"subDomainName": subDomainName,
		"pageSize":      strconv.Itoa(pageSize),
		"page":          strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListWaitingRoomsForSubDomain(subDomainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading waiting rooms",
				Detail:   formatError(err),
			})
			return nil, diags
		}

		for _, r := range res {
			if r.ID == waitingRoomID {
				return &r, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find waiting room",
		Detail:   fmt.Sprintf("Unable to find waiting room with ID = [%d]", waitingRoomID),
	})
	return nil, diags
}

// setWaitingRoomData ...
func setWaitingRoomData(d *schema.ResourceData, waitingRoom *myrasec.WaitingRoom) {
	d.SetId(strconv.Itoa(waitingRoom.ID))
	d.Set("waitingroom_id", waitingRoom.ID)
	d.Set("created", waitingRoom.Created.Format(time.RFC3339))
	d.Set("modified", waitingRoom.Modified.Format(time.RFC3339))
	d.Set("name", waitingRoom.Name)
	d.Set("vhost_id", waitingRoom.VhostId)
	d.Set("subdomain_ame", waitingRoom.SubDomainName)
	d.Set("max_concurrent", waitingRoom.MaxConcurrent)
	d.Set("session_timeout", waitingRoom.SessionTimeout)
	d.Set("wait_refresh", waitingRoom.WaitRefresh)
	d.Set("paths", waitingRoom.Paths)
	d.Set("content", "")
	d.Set("content_hash", createContentHash(waitingRoom.Content))
}
