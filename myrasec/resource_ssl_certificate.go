package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go"
	"github.com/Myra-Security-GmbH/myrasec-go/pkg/types"
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
			"domain_name": {
				Type:     schema.TypeString,
				Required: true,
			},
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
			"certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate",
				DiffSuppressFunc: func(k string, old string, new string, d *schema.ResourceData) bool {
					return true
				},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unencrypted private key",
				DiffSuppressFunc: func(k string, old string, new string, d *schema.ResourceData) bool {
					return true
				},
			},
			"subject": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Subject of the certificate",
			},
			"algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Signature algorithm of the certificate",
			},
			"valid_from": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date and time the certificate is valid from",
			},
			"valid_to": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date and time the certificate is valid to",
			},
			"fingerprint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RSA 256 fingerprint of the certificate",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Serial number of the certificate",
			},
			"subject_alternatives": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Sub domain(s) the certificate is valid for",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"wildcard": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the certificate contains a wildcard domain",
			},
			"extended_validation": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the certificate has extended validation",
			},
			"subdomains": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of subdomains where to assign the certificate",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"intermediates": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "An array of intermediate certificate(s)",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"certificate": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Certificate",
							DiffSuppressFunc: func(k string, old string, new string, d *schema.ResourceData) bool {
								return true
							},
						},
						"subject": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subject of the certificate",
						},
						"algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Signature algorithm of the certificate",
						},
						"valid_from": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Date and time the certificate is valid from",
						},
						"valid_to": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Date and time the certificate is valid to",
						},
						"fingerprint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "RSA 256 fingerprint of the certificate",
						},
						"serial_number": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Serial number of the certificate",
						},
						"issuer": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
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
	d.Set("domain_name", domainName)
	d.Set("certificate_id", cert.ID)
	d.Set("created", cert.Created.Format(time.RFC3339))
	d.Set("modified", cert.Modified.Format(time.RFC3339))
	d.Set("certificate", cert.Cert)
	d.Set("key", cert.Key)
	d.Set("subject", cert.Subject)
	d.Set("algorithm", cert.Algorithm)
	d.Set("valid_from", cert.ValidFrom.Format(time.RFC3339))
	d.Set("valid_to", cert.ValidTo.Format(time.RFC3339))
	d.Set("fingerprint", cert.Fingerprint)
	d.Set("serial_number", cert.SerialNumber)
	d.Set("subject_alternatives", cert.SubjectAlternatives)
	d.Set("wildcard", cert.Wildcard)
	d.Set("extended_validation", cert.ExtendedValidation)
	d.Set("subdomains", cert.Subdomains)

	if cert.Intermediates != nil && len(cert.Intermediates) > 0 {
		intermediates := []map[string]interface{}{}
		for _, inter := range cert.Intermediates {
			intermediates = append(intermediates, map[string]interface{}{
				"certificate":   inter.Cert,
				"subject":       inter.Subject,
				"algorithm":     inter.Algorithm,
				"fingerprint":   inter.Fingerprint,
				"serial_number": inter.SerialNumber,
				"issuer":        inter.Issuer,
			})
		}
		d.Set("intermediates", intermediates)
	}

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
	cert := &myrasec.SSLCertificate{
		Certificate: &myrasec.Certificate{
			Cert: d.Get("certificate").(string),
			//Subject:      d.Get("subject").(string),
			//Algorithm:    d.Get("algorithm").(string),
			//Fingerprint:  d.Get("fingerprint").(string),
			//SerialNumber: d.Get("serial_number").(string),
		},
		Key: d.Get("key").(string),
		//SubjectAlternatives: d.Get("subject_alternatives").([]string),
		//Wildcard:           d.Get("wildcard").(bool),
		//ExtendedValidation: d.Get("extended_validation").(bool),
		//Subdomains:         d.Get("subdomains").([]string),
	}

	if d.Get("certificate_id").(int) > 0 {
		cert.ID = d.Get("certificate_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			cert.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	cert.Certificate.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	cert.Certificate.Modified = modified

	validFrom, err := types.ParseDate(d.Get("valid_from").(string))
	if err != nil {
		return nil, err
	}
	cert.Certificate.ValidFrom = validFrom

	validTo, err := types.ParseDate(d.Get("valid_to").(string))
	if err != nil {
		return nil, err
	}
	cert.Certificate.ValidTo = validTo

	intermediates, ok := d.GetOk("intermediates")
	if !ok {
		return cert, nil
	}

	for _, intermediate := range intermediates.([]interface{}) {
		icert, err := buildSSLIntermediate(intermediate)
		if err != nil {
			return nil, err
		}

		cert.Intermediates = append(cert.Intermediates, *icert)
	}

	return cert, nil
}

//
// buildSSLIntermediate ...
//
func buildSSLIntermediate(intermediate interface{}) (*myrasec.SSLIntermediate, error) {
	cert := &myrasec.SSLIntermediate{}

	for key, val := range intermediate.(map[string]interface{}) {
		switch key {
		//case "certificate_id":
		//	cert.ID = val.(int)
		//case "modified":
		//	modified, err := types.ParseDate(val.(string))
		//	if err != nil {
		//			return nil, err
		//		}
		//		cert.Modified = modified
		//	case "created":
		//		created, err := types.ParseDate(val.(string))
		//		if err != nil {
		//			return nil, err
		//		}
		//		cert.Created = created
		case "valid_from":
			validFrom, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			cert.ValidFrom = validFrom
		case "valid_to":
			validTo, err := types.ParseDate(val.(string))
			if err != nil {
				return nil, err
			}
			cert.ValidTo = validTo
		case "certificate":
			cert.Cert = val.(string)
		case "subject":
			cert.Subject = val.(string)
		case "algorithm":
			cert.Algorithm = val.(string)
		case "fingerprint":
			cert.Fingerprint = val.(string)
		case "serial_number":
			cert.SerialNumber = val.(string)
		case "issuer":
			cert.Issuer = val.(string)
		}
	}

	return cert, nil
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
