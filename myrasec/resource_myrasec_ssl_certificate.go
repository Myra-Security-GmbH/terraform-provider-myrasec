package myrasec

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func validateNotBlank(val any, key string) (ws []string, errors []error) {
	if s, ok := val.(string); ok {
		if strings.TrimSpace(s) == "" {
			errors = append(errors, fmt.Errorf("%s must not be empty or whitespace", key))
		}
	}
	return
}

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
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Certificate",
				ValidateFunc: validateNotBlank,
			},
			"key": {
				Type:         schema.TypeString,
				Required:     true,
				Sensitive:    true,
				Description:  "Unencrypted private key",
				ValidateFunc: validateNotBlank,
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
					StateFunc: func(i any) string {
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
				ValidateFunc: validation.StringInSlice([]string{"Myra-Global-TLS-Default", "2023-mozilla-intermediate", "2023-mozilla-modern", "2026-mozilla-intermediate"}, true),
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return newValue == "" || strings.EqualFold(oldValue, newValue)
				},
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
		CustomizeDiff: func(ctx context.Context, rd *schema.ResourceDiff, i any) error {
			certificate := rd.Get("certificate")
			privateKey := rd.Get("key")

			certBlock, _ := pem.Decode([]byte(certificate.(string)))
			if certBlock == nil {
				return errors.New("Failed to decode PEM block for certificate")
			}

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				return errors.New(formatError(err))
			}

			keyBlock, _ := pem.Decode([]byte(privateKey.(string)))
			if keyBlock == nil {
				return fmt.Errorf("failed to decode PEM block for private key")
			}

			switch keyBlock.Type {
			case "RSA PRIVATE KEY":
				fallthrough
			case "PRIVATE KEY":
				privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if err != nil {
					privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
					if err != nil {
						return fmt.Errorf("failed to parse PKCS8 private key: %v", err)
					}
				}
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
func resourceMyrasecSSLCertificateCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	cert, err := buildSSLCertificate(d)
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

	if cert.CertToRefresh > 0 {
		diags = append(diags, warnIfIPLockEnabled(meta, domainID)...)
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
	diags = append(diags, resourceMyrasecSSLCertificateRead(ctx, d, meta)...)
	return diags
}

// resourceMyrasecSSLCertificateRead ...
func resourceMyrasecSSLCertificateRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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

	cert, diags := findSSLCertificate(certID, meta, domainID)
	if diags.HasError() {
		return diags
	}
	if cert == nil {
		d.SetId("")
		return nil
	}

	setSSLCertificateData(d, cert, domainName, domainID)

	return diags
}

// resourceMyrasecSSLCertificateUpdate ...
func resourceMyrasecSSLCertificateUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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

	cert, err := buildSSLCertificate(d)
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
		cert, err = updateSSLCertificateRetryingStale(client, cert, domainID, sslStaleRetryGuardFromState(d))
	} else if cert.ID > 0 {
		log.Println("[INFO] Replace certificate")
		diags = append(diags, warnIfIPLockEnabled(meta, domainID)...)
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

// sslStaleRetryGuard is the state of the certificate the plan was made against and the
// subdomains the plan sends. updateSSLCertificateRetryingStale compares the certificate on the
// server with it to decide whether a refused update may be sent again.
type sslStaleRetryGuard struct {
	// stateSubdomains are the subdomains of the certificate in the state (before this apply).
	stateSubdomains []string
	// plannedSubdomains are the subdomains the update sends.
	plannedSubdomains []string
	// stateFingerprint is the fingerprint of the certificate in the state.
	stateFingerprint string
	// stateConfigurationName is the TLS configuration of the certificate in the state.
	stateConfigurationName string
}

// sslStaleRetryGuardFromState reads the guard of an update from the resource data: the prior
// (state) values of subdomains, fingerprint and configuration_name and the planned subdomains.
func sslStaleRetryGuardFromState(d *schema.ResourceData) sslStaleRetryGuard {
	oldSubdomains, newSubdomains := d.GetChange("subdomains")
	oldFingerprint, _ := d.GetChange("fingerprint")
	oldConfigurationName, _ := d.GetChange("configuration_name")

	return sslStaleRetryGuard{
		stateSubdomains:        setToStrings(oldSubdomains),
		plannedSubdomains:      setToStrings(newSubdomains),
		stateFingerprint:       stringOrEmpty(oldFingerprint),
		stateConfigurationName: stringOrEmpty(oldConfigurationName),
	}
}

func setToStrings(v any) []string {
	set, ok := v.(*schema.Set)
	if !ok || set == nil {
		return nil
	}

	out := make([]string, 0, set.Len())
	for _, item := range set.List() {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}

	return out
}

func stringOrEmpty(v any) string {
	s, _ := v.(string)
	return s
}

// normalizeSubdomain is the form the subdomains schema stores (its StateFunc): lower case,
// without a trailing dot.
func normalizeSubdomain(s string) string {
	return strings.ToLower(myrasec.RemoveTrailingDot(s))
}

// serverChangeMatchesPlannedSubdomains reports whether the certificate on the server differs
// from the state only in subdomain assignments that this plan makes itself. The API changes
// the assignments of a certificate as a side effect of other writes in the same apply:
//   - deleting the last A/AAAA/CNAME record of a name, or renaming it away, drops the name
//     from its certificate,
//   - creating a record, with automatic certificate requests enabled for the organization,
//     assigns it to an issued certificate whose SANs (or parent wildcard) cover it,
//   - updating a managed certificate request, or uploading another certificate for the
//     name, detaches the name from this certificate or attaches it to a covering one.
//
// It is true when every subdomain the server dropped is dropped by the plan too, every
// subdomain the server gained is in the plan too, and at least one subdomain changed. It is
// false, and the refused update is reported instead of retried, when the certificate on the
// server
//   - is another certificate or was replaced (different ID or fingerprint),
//   - carries another TLS configuration,
//   - gained a subdomain the plan does not assign,
//   - lost a subdomain the plan keeps, or
//   - has the subdomains of the state (then something else changed it).
//
// So a change by someone else that the plan does not make itself is never overwritten by the
// retry.
func serverChangeMatchesPlannedSubdomains(current *myrasec.SSLCertificate, certID int, guard sslStaleRetryGuard) bool {
	if current == nil || current.Certificate == nil || current.ID != certID {
		return false
	}

	if guard.stateFingerprint == "" || current.Fingerprint != guard.stateFingerprint {
		return false
	}

	if !strings.EqualFold(current.SslConfigurationName, guard.stateConfigurationName) {
		return false
	}

	stateSet := make(map[string]bool, len(guard.stateSubdomains))
	for _, s := range guard.stateSubdomains {
		stateSet[normalizeSubdomain(s)] = true
	}

	plannedSet := make(map[string]bool, len(guard.plannedSubdomains))
	for _, s := range guard.plannedSubdomains {
		plannedSet[normalizeSubdomain(s)] = true
	}

	changed := 0

	currentSet := make(map[string]bool, len(current.Subdomains))
	for _, s := range current.Subdomains {
		n := normalizeSubdomain(s)
		if currentSet[n] {
			continue
		}
		currentSet[n] = true
		if stateSet[n] {
			continue
		}
		// Gained on the server: only acceptable when the plan assigns it as well.
		if !plannedSet[n] {
			return false
		}
		changed++
	}

	for s := range stateSet {
		if currentSet[s] {
			continue
		}
		// Dropped on the server: only acceptable when the plan drops it as well.
		if plannedSet[s] {
			return false
		}
		changed++
	}

	return changed > 0
}

// updateSSLCertificateRetryingStale sends the certificate update. The API locks optimistically:
// it refuses an update whose modified timestamp is older than the stored one with HTTP 400
// "The record has been edited in the meantime". Within one apply that happens when deleting a
// myrasec_dns_record removes its subdomain from the certificate on the server before the
// certificate update runs.
//
// On an HTTP 400 the certificate is read again. The update is sent ONCE more, with the stored
// modified timestamp and otherwise unchanged, only when the stored timestamp differs from the
// one that was sent AND serverChangeMatchesPlannedSubdomains holds. Every other case returns
// the first error unchanged: any other status, a failed re-read, an unchanged timestamp (a
// genuine validation error) and any server-side change the plan did not make itself. A refused
// retry is reported as the API answered it; there is never a third attempt.
func updateSSLCertificateRetryingStale(client *myrasec.API, cert *myrasec.SSLCertificate, domainID int, guard sslStaleRetryGuard) (*myrasec.SSLCertificate, error) {
	updated, err := client.UpdateSSLCertificate(cert, domainID)
	if err == nil {
		return updated, nil
	}

	var apiErr *myrasec.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		return nil, err
	}

	if cert.Certificate == nil || cert.Modified == nil {
		return nil, err
	}

	current, readErr := client.GetSSLCertificate(domainID, cert.ID)
	if readErr != nil {
		log.Printf("[WARN] Could not re-read SSL certificate %d after a refused update: %v", cert.ID, readErr)
		return nil, err
	}

	if current == nil || current.Certificate == nil || current.Modified == nil {
		return nil, err
	}

	if current.Modified.Equal(cert.Modified.Time) {
		return nil, err
	}

	if !serverChangeMatchesPlannedSubdomains(current, cert.ID, guard) {
		log.Printf("[WARN] SSL certificate %d was changed on the server in a way this plan did not make, not retrying the refused update", cert.ID)
		return nil, err
	}

	log.Printf("[INFO] SSL certificate %d had its subdomains changed on the server as this plan changes them (%s -> %s), retrying the update once",
		cert.ID, cert.Modified.Format(time.RFC3339), current.Modified.Format(time.RFC3339))

	retry := *cert
	retryCertificate := *cert.Certificate
	retryCertificate.Modified = current.Modified
	retry.Certificate = &retryCertificate

	return client.UpdateSSLCertificate(&retry, domainID)
}

func warnIfIPLockEnabled(meta any, domainID int) diag.Diagnostics {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	settings, err := client.ListSettings(domainID, fmt.Sprintf("ALL-%d", domainID), nil)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Could not verify the IP lock setting before refreshing the certificate",
			Detail:   formatError(err),
		})
		return diags
	}

	if settings != nil && settings.IPLock != nil && *settings.IPLock {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "IP lock is enabled for this domain",
			Detail:   "Refreshing or replacing the SSL certificate can reassign the IP address of its subdomains. IP lock is enabled for this domain but does not prevent this on a certificate refresh. Verify the subdomain IP addresses after applying and restore them if they changed.",
		})
	}

	return diags
}

// resourceMyrasecSSLCertificateDelete ...
func resourceMyrasecSSLCertificateDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
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

	cert, err := buildSSLCertificate(d)
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
func resourceMyrasecSSLCertificateImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	domainName, certID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing SSL certificate ID: [%s]", err.Error())
	}

	domainID, diags := findDomainIDByDomainName(d, meta, domainName)
	if diags.HasError() {
		return nil, diagnosticsError(diags)
	}

	cert, diags := findSSLCertificate(certID, meta, domainID)
	if diags.HasError() {
		return nil, diagnosticsError(diags)
	}
	if cert == nil {
		return nil, fmt.Errorf("unable to find SSL certificate for domain [%s] with ID = [%d]", domainName, certID)
	}
	if cert.Managed {
		return nil, fmt.Errorf("This certificate is managed by Myra")
	}

	d.SetId(strconv.Itoa(certID))
	d.Set("certificate_id", cert.ID)
	d.Set("domain_name", domainName)

	return finishImport(ctx, d, meta, resourceMyrasecSSLCertificateRead)
}

// buildSSLCertificate ...
func buildSSLCertificate(d *schema.ResourceData) (*myrasec.SSLCertificate, error) {

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
func buildSSLIntermediate(intermediate any) (*myrasec.SSLIntermediate, error) {
	cert := &myrasec.SSLIntermediate{
		Certificate: &myrasec.Certificate{
			Cert: intermediate.(map[string]any)["certificate"].(string),
		},
	}

	return cert, nil
}

// findSSLCertificate ...
func findSSLCertificate(certID int, meta any, domainID int) (*myrasec.SSLCertificate, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	c, err := client.GetSSLCertificate(domainID, certID)
	if err != nil {
		return nil, lookupDiagnostics("SSL certificate", certID, err)
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
	d.Set("valid_from", formatDateTime(cert.ValidFrom))
	d.Set("valid_to", formatDateTime(cert.ValidTo))
	d.Set("fingerprint", cert.Fingerprint)
	d.Set("serial_number", cert.SerialNumber)
	d.Set("subject_alternatives", cert.SubjectAlternatives)
	d.Set("wildcard", cert.Wildcard)
	d.Set("extended_validation", cert.ExtendedValidation)
	d.Set("subdomains", cert.Subdomains)
	d.Set("domain_id", domainID)
	d.Set("configuration_name", cert.SslConfigurationName)
}
