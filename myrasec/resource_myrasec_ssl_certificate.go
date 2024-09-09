package myrasec

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
			"domain_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Stores domain Id for subdomain.",
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
				Required:    true,
				Description: "Certificate",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Unencrypted private key",
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
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					StateFunc: func(i interface{}) string {
						return strings.ToLower(myrasec.RemoveTrailingDot(i.(string)))
					},
				},
				Description: "List of subdomains where to assign the certificate",
			},
			"cert_refresh_forced": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"cert_to_refresh": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  0,
			},
			"intermediate": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of intermediate certificates",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"certificate": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Certificate",
						},
					},
				},
			},
			"configuration_name": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Set specific ssl configuration for ciphers and protocols",
				ValidateFunc: validation.StringInSlice([]string{"Myra-Global-TLS-Default", "2023-mozilla-intermediate", "2023-mozilla-modern"}, true),
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return newValue == "" || strings.EqualFold(oldValue, newValue)
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
		CustomizeDiff: func(ctx context.Context, rd *schema.ResourceDiff, i interface{}) error {
			certificate := rd.Get("certificate")
			privateKey := rd.Get("key")

			certBlock, _ := pem.Decode([]byte(certificate.(string)))
			if certBlock == nil {
				log.Fatal("Failed to decode PEM block for certificate")
			}

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				return fmt.Errorf(formatError(err))
			}

			keyBlock, _ := pem.Decode([]byte(privateKey.(string)))
			if keyBlock == nil {
				return fmt.Errorf("failed to decode PEM block for private key")
			}

			switch keyBlock.Type {
			case "RSA PRIVATE KEY":
				privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse RSA private key: %v", err)
				}
			case "PRIVATE KEY":
				pkey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse PKCS8 private key: %v", err)
				}
				privateKey = pkey
			case "EC PRIVATE KEY":
				privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse EC private key: %v", err)
				}
			default:
				return fmt.Errorf("unsupported private key format: %s", keyBlock.Type)
			}

			switch pub := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				if priv, ok := privateKey.(*rsa.PrivateKey); ok {
					if pub.N.Cmp(priv.N) == 0 && pub.E == priv.E {
						return nil
					}
				}
			case *ecdsa.PublicKey:
				if priv, ok := privateKey.(*ecdsa.PrivateKey); ok {
					if pub.X.Cmp(priv.X) == 0 && pub.Y.Cmp(priv.Y) == 0 && pub.Curve == priv.Curve {
						return nil
					}
				}
			default:
				return fmt.Errorf("unsupported public key type")
			}

			return fmt.Errorf("private key does not match the certificate's public key")
		},
	}
}

// resourceMyrasecSSLCertificateCreate ...
func resourceMyrasecSSLCertificateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	cert, err := buildSSLCertificate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL certificate",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	resp, err := client.CreateSSLCertificate(cert, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating SSL certificate",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", resp.ID))
	return resourceMyrasecSSLCertificateRead(ctx, d, meta)
}

// resourceMyrasecSSLCertificateRead ...
func resourceMyrasecSSLCertificateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	name, ok := d.GetOk("domain_name")
	if !ok {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing resource information",
			Detail:   formatError(fmt.Errorf("[domain_name] is not set")),
		})
		return diags
	}

	domainName := name.(string)
	certID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate ID",
			Detail:   formatError(err),
		})
		return diags
	}

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	cert, diags := findSSLCertificate(certID, meta, domainName, domainID)
	if diags.HasError() || cert == nil {
		return diags
	}

	setSSLCertificateData(d, cert, domainName, domainID)

	return diags
}

// resourceMyrasecSSLCertificateUpdate ...
func resourceMyrasecSSLCertificateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	certID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating SSL certificate: %v", certID)

	cert, err := buildSSLCertificate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL certificate",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)

	domainID, domainDiag := findDomainIDByDomainName(d, meta, domainName)
	if domainDiag.HasError() {
		return domainDiag
	}

	oldCert, newCert := d.GetChange("certificate")
	oldKey, newKey := d.GetChange("key")

	if oldCert == newCert && oldKey == newKey {
		log.Println("[INFO] Update certificate")
		cert, err = client.UpdateSSLCertificate(cert, domainID)
	} else if cert.ID > 0 {
		log.Println("[INFO] Replace certificate")
		cert.CertToRefresh = cert.ID
		cert.ID = 0
		cert, err = client.CreateSSLCertificate(cert, domainID)
	} else {
		log.Println("[INFO] Create certificate")
		cert.ID = 0
		cert, err = client.CreateSSLCertificate(cert, domainID)
	}

	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating SSL certificate",
			Detail:   formatError(err),
		})
		return diags
	}

	setSSLCertificateData(d, cert, domainName, domainID)

	return diags
}

// resourceMyrasecSSLCertificateDelete ...
func resourceMyrasecSSLCertificateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	certID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting SSL certificate: %v", certID)

	cert, err := buildSSLCertificate(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL certificate",
			Detail:   formatError(err),
		})
		return diags
	}

	domainName := d.Get("domain_name").(string)

	domainID, diags := findDomainIDByDomainName(d, meta, domainName)
	if diags.HasError() {
		return diags
	}

	_, err = client.DeleteSSLCertificate(cert, domainID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting SSL certificate",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecSSLCertificateImport ...
func resourceMyrasecSSLCertificateImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	domainName, certID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing SSL certificate ID: [%s]", err.Error())
	}

	domainID, diags := findDomainIDByDomainName(d, meta, domainName)
	if diags.HasError() {
		return nil, fmt.Errorf("unable to find domainID by domainName: [%s]", domainName)
	}

	cert, diags := findSSLCertificate(certID, meta, domainName, domainID)
	if diags.HasError() || cert == nil {
		return nil, fmt.Errorf("unable to find SSL certificate for domain [%s] with ID = [%d]", domainName, certID)
	}

	d.SetId(strconv.Itoa(certID))
	d.Set("certificate_id", cert.ID)
	d.Set("domain_name", domainName)

	resourceMyrasecSSLCertificateRead(ctx, d, meta)
	return []*schema.ResourceData{d}, nil
}

// buildSSLCertificate ...
func buildSSLCertificate(d *schema.ResourceData, meta interface{}) (*myrasec.SSLCertificate, error) {

	cert := &myrasec.SSLCertificate{
		Certificate: &myrasec.Certificate{},
	}

	subdomains := d.Get("subdomains").(*schema.Set)
	for _, sd := range subdomains.List() {
		cert.Subdomains = append(cert.Subdomains, sd.(string))
	}

	crt, ok := d.GetOk("certificate")
	if ok {
		cert.Certificate.Cert = crt.(string)
	}

	key, ok := d.GetOk("key")
	if ok {
		cert.Key = key.(string)
	}

	ctr, ok := d.GetOk("cert_to_refresh")
	if ok {
		cert.CertToRefresh = ctr.(int)
	}

	crf, ok := d.GetOk("cert_refresh_forced")
	if ok {
		cert.CertRefreshForced = crf.(bool)
	}

	if d.Get("certificate_id").(int) > 0 {
		cert.ID = d.Get("certificate_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			cert.ID = id
		}
	}

	configurationName, ok := d.GetOk("configuration_name")
	if ok {
		cert.SslConfigurationName = configurationName.(string)
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

	intermediates, ok := d.GetOk("intermediate")
	if !ok {
		return cert, nil
	}

	for _, intermediate := range intermediates.(*schema.Set).List() {
		icert, err := buildSSLIntermediate(intermediate)
		if err != nil {
			return nil, err
		}

		cert.Intermediates = append(cert.Intermediates, *icert)
	}

	return cert, nil
}

// buildSSLIntermediate ...
func buildSSLIntermediate(intermediate interface{}) (*myrasec.SSLIntermediate, error) {
	cert := &myrasec.SSLIntermediate{
		Certificate: &myrasec.Certificate{
			Cert: intermediate.(map[string]interface{})["certificate"].(string),
		},
	}

	return cert, nil
}

// findSSLCertificate ...
func findSSLCertificate(certID int, meta interface{}, domainName string, domainID int) (*myrasec.SSLCertificate, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	c, err := client.GetSSLCertificate(domainID, certID)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error loading SSL certificate",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	if c != nil {
		return c, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find SSL certificate",
		Detail:   fmt.Sprintf("Unable to find SSL certificate with ID = [%d]", certID),
	})
	return nil, diags
}

// setSSLCertificateData ...
func setSSLCertificateData(d *schema.ResourceData, cert *myrasec.SSLCertificate, domainName string, domainID int) {
	d.SetId(strconv.Itoa(cert.ID))
	d.Set("certificate_id", cert.ID)
	d.Set("domain_name", domainName)
	d.Set("created", cert.Created.Format(time.RFC3339))
	d.Set("modified", cert.Modified.Format(time.RFC3339))
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
	d.Set("domain_id", domainID)
	d.Set("configuration_name", cert.SslConfigurationName)
}
