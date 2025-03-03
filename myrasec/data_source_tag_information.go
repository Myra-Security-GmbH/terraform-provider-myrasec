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

// dataSourceMyrasecInformation ...
func dataSourceMyrasecTagInformation() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecTagInformationRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tag_id": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"key": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"information": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"modified": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"tag_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"key": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"comment": {
							Type:     schema.TypeString,
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

// dataSourceMyrasecTagInformationRead ...
func dataSourceMyrasecTagInformationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareTagInformationFilter(d.Get("filter"))
	if f == nil {
		f = &tagInformationFilter{}
	}

	params := map[string]string{}
	if len(f.key) > 0 {
		params["search"] = f.key
	}

	informationData := make([]interface{}, 0)
	if f.tagId > 0 {
		information, diags := createInformationData(f.tagId, meta, params)
		if diags.HasError() {
			return diags
		}
		informationData = append(informationData, information...)
	} else {
		tags, err := listTags(meta, params)
		if err != nil {
			return err
		}

		for _, tag := range tags {
			information, diags := createInformationData(tag.ID, meta, params)
			if diags.HasError() {
				return diags
			}
			informationData = append(informationData, information...)
		}
	}

	if err := d.Set("information", informationData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

// createInformationData
func createInformationData(tagId int, meta interface{}, params map[string]string) ([]interface{}, diag.Diagnostics) {
	information, diags := listTagInformation(tagId, meta, params)
	informationData := make([]interface{}, 0)
	if diags.HasError() {
		return informationData, diags
	}

	for _, i := range information {
		informationData = append(informationData, map[string]interface{}{
			"id":       i.ID,
			"created":  i.Created.Format(time.RFC3339),
			"modified": i.Modified.Format(time.RFC3339),
			"tag_id":   tagId,
			"key":      i.Key,
			"value":    i.Value,
			"comment":  i.Comment,
		})
	}

	return informationData, nil
}

// prepareTagInformationFilter fetches the panic that can happen in parseTagInformationFilter
func prepareTagInformationFilter(d interface{}) *tagInformationFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareTagInformationFilter", r)
		}
	}()

	return parseTagInformationFilter(d)
}

// parseTagInformationFilter converts the filter data to a tagInformationFilter struct
func parseTagInformationFilter(d interface{}) *tagInformationFilter {
	cfg := d.([]interface{})
	f := &tagInformationFilter{}

	m := cfg[0].(map[string]interface{})

	tagId, ok := m["tag_id"]
	if ok {
		f.tagId = tagId.(int)
	}

	key, ok := m["key"]
	if ok {
		f.key = key.(string)
	}

	return f
}

// listTagInformation ...
func listTagInformation(tagId int, meta interface{}, params map[string]string) ([]myrasec.TagInformation, diag.Diagnostics) {
	var diags diag.Diagnostics
	var information []myrasec.TagInformation
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListTagInformation(tagId, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching tag information",
				Detail:   formatError(err),
			})
			return information, diags
		}
		information = append(information, res...)
		if len(res) < pageSize {
			break
		}
		page++
	}

	return information, diags
}

// tagInformationFilter struct ...
type tagInformationFilter struct {
	tagId int
	key   string
}
