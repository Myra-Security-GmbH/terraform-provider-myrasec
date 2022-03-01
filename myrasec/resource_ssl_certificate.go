package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMyrasecSSLCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecSSLCertificateCreate,
		ReadContext:   resourceMyrasecSSLCertificateRead,
		UpdateContext: resourceMyrasecSSLCertificateUpdate,
		DeleteContext: resourceMyrasecSSLCertificateDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecSSLCertificateImport,
		},
		Schema: map[string]*schema.Schema{
			"certificate_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the SSL certificate.",
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
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

//
// resourceMyrasecSSLCertificateCreate ...
//
func resourceMyrasecSSLCertificateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	cert, err := buildSSLCertificate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL certificate",
			Detail:   err.Error(),
		})
		return diags
	}

	resp, err := client.CreateSSLCertificate(cert, d.Get("domain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating SSL certificate",
			Detail:   err.Error(),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecSSLCertificateRead(ctx, d, meta)
}

//
// resourceMyrasecSSLCertificateRead ...
//
func resourceMyrasecSSLCertificateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("domain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   "[domain_name] is not set",
		})
		return diags
	}

	domainName := name.(string)
	certID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate ID",
			Detail:   err.Error(),
		})
		return diags
	}

	cert, diags := findSSLCertificate(certID, meta, domainName)
	if diags.HasError() || cert == nil {
		return diags
	}

	d.SetId(strconv.Itoa(certID))
	d.Set("filter_id", cert.ID)
	d.Set("created", cert.Created.Format(time.RFC3339))
	d.Set("modified", cert.Modified.Format(time.RFC3339))
	d.Set("domain_name", domainName)
	// @TODO - define schema
	return diags
}

//
// resourceMyrasecSSLCertificateUpdate ...
//
func resourceMyrasecSSLCertificateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	certID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Updating SSL certificate: %v", certID)

	cert, err := buildSSLCertificate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL certificate",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.UpdateSSLCertificate(cert, d.Get("domain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating SSL certificate",
			Detail:   err.Error(),
		})
		return diags
	}

	return resourceMyrasecIPFilterRead(ctx, d, meta)
}

//
// resourceMyrasecSSLCertificateDelete ...
//
func resourceMyrasecSSLCertificateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	certID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate ID",
			Detail:   err.Error(),
		})
		return diags
	}

	log.Printf("[INFO] Deleting SSL certificate: %v", certID)

	cert, err := buildSSLCertificate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL certificate",
			Detail:   err.Error(),
		})
		return diags
	}

	_, err = client.DeleteSSLCertificate(cert, d.Get("domain_name").(string))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting SSL certificate",
			Detail:   err.Error(),
		})
		return diags
	}
	return diags
}

//
// resourceMyrasecSSLCertificateImport ...
//
func resourceMyrasecSSLCertificateImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	domainName, certID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("Error parsing SSL certificate ID: [%s]", err.Error())
	}

	cert, diags := findSSLCertificate(certID, meta, domainName)
	if diags.HasError() || cert == nil {
		return nil, fmt.Errorf("Unable to find SSL certificate for domain [%s] with ID = [%d]", domainName, certID)
	}

	d.SetId(strconv.Itoa(certID))
	d.Set("certificate_id", cert.ID)
	d.Set("domain_name", domainName)

	resourceMyrasecSSLCertificateRead(ctx, d, meta)
	return []*schema.ResourceData{d}, nil
}

//
// buildSSLCertificate ...
//
func buildSSLCertificate(d *schema.ResourceData, meta interface{}) (*myrasec.SSLCertificate, error) {
	//@TODO

	return nil, nil
}

//
// findSSLCertificate ...
//
func findSSLCertificate(certID int, meta interface{}, domainName string) (*myrasec.SSLCertificate, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	page := 1
	params := map[string]string{
		"pageSize": "50",
		"page":     strconv.Itoa(page),
	}

	for {
		params["page"] = strconv.Itoa(page)
		res, err := client.ListSSLCertificates(domainName, params)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading SSL certificates",
				Detail:   err.Error(),
			})
			return nil, diags
		}

		for _, c := range res {
			if c.ID == certID {
				return &c, diags
			}
		}

		if len(res) < 50 {
			break
		}
		page++
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find SSL certificate",
		Detail:   fmt.Sprintf("Unable to find SSL certificate with ID = [%d]", certID),
	})
	return nil, diags

}
