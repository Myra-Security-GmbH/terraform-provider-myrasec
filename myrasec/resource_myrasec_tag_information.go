package myrasec

import (
	"context"
	"strconv"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

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
			"informations": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

func resourceMyrasecTagInformationCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	tagId := d.Get("tag_id").(int)
	informations := d.Get("informations")
	_, err := client.UpdateTagInformation(tagId, informations.(map[string]interface{}))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating tag informations",
			Detail:   formatError(err),
		})
		return diags
	}

	return resourceMyrasecTagInformationRead(ctx, d, meta)
}

func resourceMyrasecTagInformationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	tagId := d.Get("tag_id")
	tagInformation, err := client.GetTagInformation(tagId.(int))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error loading tag informations",
			Detail:   formatError(err),
		})
		return diags
	}

	setTagInformationData(d, tagInformation)
	return diags
}

func resourceMyrasecTagInformationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	tagId := d.Get("tag_id").(int)
	_, err := client.UpdateTagInformation(tagId, d.Get("informations").(map[string]interface{}))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating tag informations",
			Detail:   formatError(err),
		})
		return diags
	}

	return resourceMyrasecTagInformationRead(ctx, d, meta)
}

func resourceMyrasecTagInformationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)
	var diags diag.Diagnostics

	tagId := d.Get("tag_id").(int)
	_, err := client.UpdateTagInformation(tagId, map[string]interface{}{})
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating tag informations",
			Detail:   formatError(err),
		})
		return diags
	}

	return resourceMyrasecTagInformationRead(ctx, d, meta)

}

func resourceMyrasecTagInformationImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	tagID := d.Id()

	d.SetId(tagID)
	d.Set("tag_id", tagID)

	resourceMyrasecTagInformationRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

func setTagInformationData(d *schema.ResourceData, data map[string]interface{}) {
	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))
	d.Set("tag_id", data["id"])
	d.Set("informations", data["informations"])
	d.Set("created", data["created"])
	d.Set("updated", data["updated"])
}
