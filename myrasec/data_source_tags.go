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
						"match": {
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
						"organization": {
							Type:     schema.TypeInt,
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

func dataSourceMyrasecTagsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	f := prepareTagFilter(d.Get("filter"))
	if f == nil {
		f = &tagFilter{}
	}

	params := map[string]string{}
	if len(f.path) > 0 {
		params["search"] = f.path
	}

	tags, diags := listTags(meta, params)
	if diags.HasError() {
		return diags
	}

	tagData := make([]interface{}, 0)
	for _, t := range tags {
		tag := map[string]interface{}{
			"id":           t.ID,
			"created":      t.Created.Format(time.RFC3339),
			"modified":     t.Modified.Format(time.RFC3339),
			"type":         t.Type,
			"organization": t.Organization,
		}

		assignments := make([]interface{}, 0)
		if t.Assignments != nil && len(t.Assignments) > 0 {
			for _, a := range t.Assignments {
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
		}
		tagData = append(tagData, tag)
	}

	if err := d.Set("tags", tagData); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

//
// prepareTagFilter fetches the panic that can happen in parseTagFilter
//
func prepareTagFilter(d interface{}) *tagFilter {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[DEBUG] recovered in prepareTagFilter", r)
		}
	}()

	return parseTagFilter(d)
}

//
// parseTagFilter converts the filter data to a tagFilter struct
//
func parseTagFilter(d interface{}) *tagFilter {
	cfg := d.([]interface{})
	f := &tagFilter{}

	m := cfg[0].(map[string]interface{})

	path, ok := m["path"]
	if ok {
		f.path = path.(string)
	}

	return f
}

//
// listTags
//
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

//
// tagFilter struct ...
//
type tagFilter struct {
	path string
}
