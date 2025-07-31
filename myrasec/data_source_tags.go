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

// dataSourceMyrasecTags ...
func dataSourceMyrasecTags() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMyrasecTagsRead,
		Schema: map[string]*schema.Schema{
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"tags": {
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
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"sort": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"global": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"assignments": {
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
									"type": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"title": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"subdomain_name": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
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

// dataSourceMyrasecTagsRead
func dataSourceMyrasecTagsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareTagFilter(d.Get("filter"))
	if f == nil {
		f = &tagFilter{}
	}

	params := map[string]string{}
	if len(f.name) > 0 {
		params["search"] = f.name
	}

	tags, diags := listTags(meta, params)
	if diags.HasError() {
		return diags
	}

	tagData := make([]interface{}, 0)
	for _, t := range tags {
		res, err := getTag(t.ID, meta)
		if err != nil {
			return diags
		}

		tag := map[string]interface{}{
			"id":       res.ID,
			"created":  res.Created.Format(time.RFC3339),
			"modified": res.Modified.Format(time.RFC3339),
			"name":     res.Name,
			"type":     res.Type,
			"sort":     res.Sort,
			"global":   res.Global,
		}

		assignments := make([]interface{}, 0)
		for _, a := range res.Assignments {
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
		tag["assignments"] = assignments

		tagData = append(tagData, tag)
	}

	if err := d.Set("tags", tagData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

// prepareTagFilter fetches the panic that can happen in parseTagFilter
func prepareTagFilter(d interface{}) *tagFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareTagFilter", r)
		}
	}()
	return parseTagFilter(d)
}

func parseTagFilter(d interface{}) *tagFilter {
	cfg := d.([]interface{})
	f := &tagFilter{}

	m := cfg[0].(map[string]interface{})

	name, ok := m["name"]
	if ok {
		f.name = name.(string)
	}

	return f
}

// listTags
func listTags(meta interface{}, params map[string]string) ([]myrasec.Tag, diag.Diagnostics) {
	var diags diag.Diagnostics
	var tags []myrasec.Tag
	pageSize := 250

	client := meta.(*myrasec.API)

	params["pageSize"] = strconv.Itoa(pageSize)
	page := 1

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListTags(params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error fetching tags",
				Detail:   formatError(err),
			})
			return tags, diags
		}
		tags = append(tags, res...)
		if len(tags) < pageSize {
			break
		}
		page++
	}
	return tags, diags
}

// getTag
func getTag(tagId int, meta interface{}) (*myrasec.Tag, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)
	tag, err := client.GetTag(tagId)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error to get tag",
			Detail:   formatError(err),
		})
		return nil, diags
	}
	return tag, nil
}

// tagFilter struct ...
type tagFilter struct {
	name string
}
