package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// resourceMyrasecTagInformation ...
func resourceMyrasecTagInformation() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecTagInformationCreate,
		ReadContext:   resourceMyrasecTagInformationRead,
		UpdateContext: resourceMyrasecTagInformationUpdate,
		DeleteContext: resourceMyrasecTagInformationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecTagInformationImport,
		},
		Schema: map[string]*schema.Schema{
			"tag_id": {
				Type:        schema.TypeInt,
				Required:    true,
				ForceNew:    true,
				Description: "The Id of the tag for the tag information.",
			},
			"information_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the information.",
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
			"key": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The information Key.",
			},
			"value": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The information Value.",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "A comment to describe this information.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecTagInformationCreate ...
func resourceMyrasecTagInformationCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	information, err := buildTagInformation(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building tag information",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	information, err = client.CreateTagInformation(information, tagID.(int))
	if err == nil {
		setTagInformationData(d, information, tagID.(int))
		return diags
	}

	info, errImport := importExistingTagInformation(information, tagID.(int), meta)
	if errImport != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Error creating tag information",
			Detail:   formatError(err),
		})
		return diags
	}

	setTagInformationData(d, info, tagID.(int))

	return diags
}

// resourceMyrasecTagInformationRead ...
func resourceMyrasecTagInformationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	informationID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing tag information ID",
			Detail:   formatError(err),
		})
		return diags
	}

	info, diags := findTagInformation(informationID, tagID.(int), meta)
	if diags.HasError() || info == nil {
		return diags
	}

	setTagInformationData(d, info, tagID.(int))

	return diags
}

// resourceMyrasecTagInformationUpdate ...
func resourceMyrasecTagInformationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	informationID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing tag information ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating tag information: %v", informationID)
	information, err := buildTagInformation(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building tag information",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	information, err = client.UpdateTagInformation(information, tagID.(int))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating tag information",
			Detail:   formatError(err),
		})
	}

	setTagInformationData(d, information, tagID.(int))

	return diags
}

// resourceMyrasecTagInformationDelete ...
func resourceMyrasecTagInformationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	information, err := buildTagInformation(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building tag information",
			Detail:   formatError(err),
		})
		return diags
	}

	tagID, ok := d.GetOk("tag_id")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[tag_id] is not set")),
		})
		return diags
	}

	_, err = client.DeleteTagInformation(information, tagID.(int))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting tag information",
			Detail:   formatError(err),
		})
		return diags
	}

	return diags
}

// resourceMyrasecTagInformationImport ...
func resourceMyrasecTagInformationImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	tag, informationID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing tag information ID: [%s]", err.Error())
	}

	log.Printf("Importing tag information with ID [%d] and tagID [%v]", informationID, tag)

	tagID, err := strconv.Atoi(tag)
	if err != nil {
		return nil, fmt.Errorf("unable to convert tagID to int")
	}

	d.SetId(strconv.Itoa(informationID))
	d.Set("tag_id", tagID)
	resourceMyrasecTagInformationRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

// buildTagInformation ...
func buildTagInformation(d *schema.ResourceData, meta interface{}) (*myrasec.TagInformation, error) {
	information := &myrasec.TagInformation{
		Key:     d.Get("key").(string),
		Value:   d.Get("value").(string),
		Comment: d.Get("comment").(string),
	}

	if d.Get("information_id").(int) > 0 {
		information.ID = d.Get("information_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			information.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	information.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	information.Modified = modified

	return information, nil
}

// findTagInformation
func findTagInformation(informationID int, tagID int, meta interface{}) (*myrasec.TagInformation, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	pageSize := 250
	params := map[string]string{
		"pageSize": strconv.Itoa(pageSize),
		"page":     strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)

		res, err := client.ListTagInformation(tagID, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading tag information",
				Detail:   formatError(err),
			})
		}

		for _, s := range res {
			if s.ID == informationID {
				return &s, diags
			}
		}

		if len(res) < pageSize {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find tag information",
		Detail:   fmt.Sprintf("Unable to find tag information with ID = [%d]", informationID),
	})

	return nil, diags
}

// setTagInformationData
func setTagInformationData(d *schema.ResourceData, information *myrasec.TagInformation, tagID int) {
	d.SetId(strconv.Itoa(information.ID))
	d.Set("information_id", information.ID)
	d.Set("tag_id", tagID)

	if information.Created != nil {
		d.Set("created", information.Created.Format(time.RFC3339))
	}

	if information.Modified != nil {
		d.Set("modified", information.Modified.Format(time.RFC3339))
	}

	d.Set("key", information.Key)
	d.Set("valye", information.Value)
	d.Set("comment", information.Comment)
}

// importExistingTagInformation
func importExistingTagInformation(info *myrasec.TagInformation, tagID int, meta interface{}) (*myrasec.TagInformation, error) {
	client := meta.(*myrasec.API)

	params := map[string]string{
		"search": info.Key,
	}

	information, err := client.ListTagInformation(tagID, params)
	if err != nil {
		return nil, err
	}

	if len(information) <= 0 {
		return nil, fmt.Errorf("unable to find existing tag information for automatic import")
	}

	for _, i := range information {
		if i.Key != info.Key || i.Value != info.Value || i.Comment != info.Comment {
			continue
		}
		return &i, nil
	}

	return nil, fmt.Errorf("unable to find existing tag information for automatic import")
}
