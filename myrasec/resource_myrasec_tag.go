package myrasec

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"golang.org/x/net/context"
)

// resourceMyrasecTag
func resourceMyrasecTag() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecTagCreate,
		ReadContext:   resourceMyrasecTagRead,
		UpdateContext: resourceMyrasecTagUpdate,
		DeleteContext: resourceMyrasecTagDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecTagImport,
		},
		Schema: map[string]*schema.Schema{
			"tag_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the tag",
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
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Name of the tag",
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				StateFunc: func(i interface{}) string {
					return strings.ToUpper(i.(string))
				},
				ValidateFunc: validation.StringInSlice([]string{"CACHE", "CONFIG", "RATE_LIMIT", "WAF"}, true),
				Description:  "The Type of the tag",
			},
			"assignments": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "ID of the tag assignment",
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
							Type:     schema.TypeString,
							Required: true,
							StateFunc: func(i interface{}) string {
								return strings.ToUpper(i.(string))
							},
							ValidateFunc: validation.StringInSlice([]string{"DOMAIN", "SUBDOMAIN"}, true),
							Description:  "The Type of the tag assignment",
						},
						"title": {
							Type:     schema.TypeString,
							Required: true,
							StateFunc: func(i interface{}) string {
								return myrasec.RemoveTrailingDot(i.(string))
							},
							Description: "The Title of the tag assignment",
						},
						"subdomain_name": {
							Type:     schema.TypeString,
							Required: true,
							StateFunc: func(i interface{}) string {
								return myrasec.RemoveTrailingDot(i.(string))
							},
							DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
								return myrasec.RemoveTrailingDot(old) == myrasec.RemoveTrailingDot(new)
							},
							Description: "The subdomain of the tag assignment",
						},
					},
				},
				Set: func(a interface{}) int {
					obj := a.(map[string]interface{})

					assignmentType := strings.ToUpper(obj["type"].(string))
					title := myrasec.RemoveTrailingDot(obj["title"].(string))
					name := myrasec.RemoveTrailingDot(obj["subdomain_name"].(string))

					h := sha256.New()
					h.Write([]byte(assignmentType))
					h.Write([]byte(title))
					h.Write([]byte(name))

					hash := int(binary.BigEndian.Uint64(h.Sum(nil)))
					return hash
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecTagCreate ...
func resourceMyrasecTagCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	tag, err := buildTag(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building Tag",
			Detail:   formatError(err),
		})
		return diags
	}

	resp, err := client.CreateTag(tag)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating tag",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecTagRead(ctx, d, meta)
}

// resourceMyrasecTagRead
func resourceMyrasecTagRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	tagId, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing tag ID",
			Detail:   formatError(err),
		})
		return diags
	}

	tag, diags := findTag(tagId, meta)
	if tag == nil {
		d.SetId("")
		return diags
	}

	setTagData(d, tag)

	return diags
}

// resourceMyrasecTagUpdate ...
func resourceMyrasecTagUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	tag, err := buildTag(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building Tag",
			Detail:   formatError(err),
		})
		return diags
	}

	resp, err := client.UpdateTag(tag)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating tag",
			Detail:   formatError(err),
		})
		return diags
	}

	setTagData(d, resp)

	return resourceMyrasecTagRead(ctx, d, meta)
}

// resourceMyrasecTagDelete ...
func resourceMyrasecTagDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	tag, err := buildTag(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building Tag",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.DeleteTag(tag)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting tag",
			Detail:   formatError(err),
		})
		return diags
	}

	return diags
}

// resourceMyrasecTagImport
func resourceMyrasecTagImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	_, tagID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing tag id with id: [%s]", err.Error())
	}

	tag, diags := findTag(tagID, meta)
	if diags.HasError() || tag == nil {
		return nil, fmt.Errorf("unable to find tag with id [%d]", tagID)
	}
	d.SetId(strconv.Itoa(tagID))
	d.Set("tag_id", tag.ID)

	resourceMyrasecTagRead(ctx, d, meta)
	return []*schema.ResourceData{d}, nil
}

// findTag
func findTag(tagId int, meta interface{}) (*myrasec.Tag, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	t, err := client.GetTag(tagId)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error loading tag",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	if t != nil {
		return t, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Error,
		Summary:  "Unable to find tag",
		Detail:   fmt.Sprintf("Unable to find tag with ID [%d]", tagId),
	})
	return nil, diags
}

// buildTag ...
func buildTag(d *schema.ResourceData, meta interface{}) (*myrasec.Tag, error) {
	tag := &myrasec.Tag{
		Name: d.Get("name").(string),
		Type: d.Get("type").(string),
	}

	if d.Get("tag_id").(int) > 0 {
		tag.ID = d.Get("tag_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err != nil && id > 0 {
			tag.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	tag.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	tag.Modified = modified

	assignments := d.Get("assignments").(*schema.Set)
	for _, assignment := range assignments.List() {
		tagAssignment, err := buildTagAssignments(assignment)
		if err != nil {
			return nil, err
		}
		tag.Assignments = append(tag.Assignments, *tagAssignment)
	}

	return tag, nil
}

// buildTagAssignment
func buildTagAssignments(assignment interface{}) (*myrasec.TagAssignment, error) {
	tagAssignment := &myrasec.TagAssignment{
		Type:          assignment.(map[string]interface{})["type"].(string),
		Title:         assignment.(map[string]interface{})["title"].(string),
		SubDomainName: assignment.(map[string]interface{})["subdomain_name"].(string),
	}

	if assignment.(map[string]interface{})["id"].(int) > 0 {
		tagAssignment.ID = assignment.(map[string]interface{})["id"].(int)
	}

	created, err := types.ParseDate(assignment.(map[string]interface{})["created"].(string))
	if err != nil {
		return nil, err
	}
	tagAssignment.Created = created

	modified, err := types.ParseDate(assignment.(map[string]interface{})["modified"].(string))
	if err != nil {
		return nil, err
	}
	tagAssignment.Modified = modified

	return tagAssignment, nil
}

// setTagData
func setTagData(d *schema.ResourceData, tag *myrasec.Tag) {
	d.SetId(strconv.Itoa(tag.ID))
	d.Set("tag_id", tag.ID)
	d.Set("name", tag.Name)
	d.Set("type", tag.Type)
	d.Set("created", tag.Created.Format(time.RFC3339))
	d.Set("modified", tag.Modified.Format(time.RFC3339))

	assignments := make([]interface{}, 0)
	for _, a := range tag.Assignments {
		if a.SubDomainName == "" {
			a.SubDomainName = a.Title
		}
		assignment := map[string]interface{}{
			"id":             a.ID,
			"created":        a.Created.Format(time.RFC3339),
			"modified":       a.Modified.Format(time.RFC3339),
			"type":           a.Type,
			"title":          a.Title,
			"subdomain_name": a.SubDomainName,
		}
		assignments = append(assignments, assignment)
	}
	d.Set("assignments", assignments)
}
