package myrasec

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var (
	sslCertificateRequestProviders = []string{
		myrasec.SSLProviderLetsEncrypt,
		myrasec.SSLProviderSectigo,
		myrasec.SSLProviderDTrust,
	}

	sslCertificateRequestAlgorithms = []string{
		myrasec.SSLCertificateRequestAlgorithmRSA2048,
		myrasec.SSLCertificateRequestAlgorithmRSA4096,
		myrasec.SSLCertificateRequestAlgorithmRSA8192,
		myrasec.SSLCertificateRequestAlgorithmECDSA256,
		myrasec.SSLCertificateRequestAlgorithmECDSA384,
	}

	// sslCertificateRequestLetsEncryptAlgorithms lists the key algorithms Let's Encrypt accepts
	sslCertificateRequestLetsEncryptAlgorithms = []string{
		myrasec.SSLCertificateRequestAlgorithmRSA2048,
		myrasec.SSLCertificateRequestAlgorithmECDSA256,
		myrasec.SSLCertificateRequestAlgorithmECDSA384,
	}

	sslCertificateRequestSignatureAlgorithms = []string{
		myrasec.SSLCertificateRequestSignatureAlgorithmSHA256,
		myrasec.SSLCertificateRequestSignatureAlgorithmSHA384,
		myrasec.SSLCertificateRequestSignatureAlgorithmSHA512,
	}
)

// resourceMyrasecSSLCertificateRequest ...
func resourceMyrasecSSLCertificateRequest() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecSSLCertificateRequestCreate,
		ReadContext:   resourceMyrasecSSLCertificateRequestRead,
		UpdateContext: resourceMyrasecSSLCertificateRequestUpdate,
		DeleteContext: resourceMyrasecSSLCertificateRequestDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecSSLCertificateRequestImport,
		},
		Schema: map[string]*schema.Schema{
			"request_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the managed certificate request.",
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
			"certificate_provider": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "The certificate provider the certificate is requested from. Valid values: LETS_ENCRYPT, SECTIGO, DTRUST.",
				ValidateFunc: validation.StringInSlice(sslCertificateRequestProviders, false),
			},
			"algorithm": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "Key algorithm of the requested certificate. Valid values: RSA2048, RSA4096, RSA8192, ECDSA256, ECDSA384. Immutable, a change replaces the request.",
				ValidateFunc: validation.StringInSlice(sslCertificateRequestAlgorithms, false),
			},
			"subject_alternative_names": {
				Type:        schema.TypeSet,
				Required:    true,
				MinItems:    1,
				Description: "Names the certificate has to cover, e.g. www.example.com or *.example.com. Every name must belong to a domain registered in the Myra system.",
				Set:         hashDomainName,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					StateFunc: func(i any) string {
						return normalizeDomainName(i.(string))
					},
				},
			},
			"subdomains": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Subdomains the issued certificate is assigned to.",
				Set:         hashDomainName,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					StateFunc: func(i any) string {
						return normalizeDomainName(i.(string))
					},
				},
			},
			"ssl_provider_credentials_id": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "ID of the SSL provider credentials used for the issuance. Required for SECTIGO and DTRUST, ignored for LETS_ENCRYPT.",
			},
			"renewal_interval": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      0,
				Description:  "Days before expiry at which the certificate is renewed. 0 means the system default. Accepted for SECTIGO and DTRUST only.",
				ValidateFunc: validation.IntAtLeast(0),
			},
			"signature_algorithm": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Signature algorithm of the requested certificate. Valid values: SHA256, SHA384, SHA512. Empty means the system default. Accepted for SECTIGO and DTRUST only.",
				ValidateFunc: validation.StringInSlice(sslCertificateRequestSignatureAlgorithms, false),
			},
			"configuration_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SSL configuration (TLS profile) applied to the certificates issued for the request. Valid names are listed by the myrasec_ssl_configurations data source.",
				// The API has no call to reset the profile, removing the attribute keeps the stored one.
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return newValue == ""
				},
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Issuance status: OPEN, WAITING_FOR_CNAME, CREATED or FAILED.",
			},
			"failure_reason": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Reason code when the status is FAILED.",
			},
			"customer_actionable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the failure reason is a DNS or CNAME issue the customer can resolve.",
			},
			"multi_domain": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the subject alternative names span more than one domain.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
		CustomizeDiff: func(ctx context.Context, rd *schema.ResourceDiff, i any) error {
			return validateSSLCertificateRequestDiff(rd)
		},
	}
}

// validateSSLCertificateRequestDiff checks the provider specific constraints of a request at plan time
func validateSSLCertificateRequestDiff(rd *schema.ResourceDiff) error {
	if rd.NewValueKnown("subject_alternative_names") {
		names := expandStringSet(rd.Get("subject_alternative_names"))
		if name, wildcard := findRedundantSAN(names); name != "" {
			return fmt.Errorf("subject_alternative_names: %s is covered by %s and would be dropped by the API, remove it", name, wildcard)
		}
	}

	// Values interpolated from other resources can be unknown at plan time. The
	// checks below are skipped for unknown values and left to the API.
	algorithm, algorithmKnown := knownString(rd, "algorithm")
	signatureAlgorithm, signatureAlgorithmKnown := knownString(rd, "signature_algorithm")
	provider, providerKnown := knownString(rd, "certificate_provider")

	if algorithmKnown && signatureAlgorithmKnown &&
		signatureAlgorithm == myrasec.SSLCertificateRequestSignatureAlgorithmSHA512 && strings.HasPrefix(algorithm, "ECDSA") {
		return errors.New("signature_algorithm SHA512 cannot be combined with an ECDSA algorithm")
	}

	if !providerKnown {
		return nil
	}

	if provider == myrasec.SSLProviderLetsEncrypt {
		if algorithmKnown && !StringInSlice(algorithm, sslCertificateRequestLetsEncryptAlgorithms) {
			return fmt.Errorf("certificate_provider LETS_ENCRYPT accepts the algorithms %s only", strings.Join(sslCertificateRequestLetsEncryptAlgorithms, ", "))
		}
		if signatureAlgorithmKnown && signatureAlgorithm != "" {
			return errors.New("signature_algorithm is accepted for certificate_provider SECTIGO and DTRUST only")
		}
		if rd.NewValueKnown("renewal_interval") && rd.Get("renewal_interval").(int) != 0 {
			return errors.New("renewal_interval is accepted for certificate_provider SECTIGO and DTRUST only")
		}
		// The API ignores the credentials for Let's Encrypt and returns 0, a configured
		// value would leave a permanent diff.
		if rd.NewValueKnown("ssl_provider_credentials_id") && rd.Get("ssl_provider_credentials_id").(int) != 0 {
			return errors.New("ssl_provider_credentials_id is ignored for certificate_provider LETS_ENCRYPT, remove it")
		}
		return nil
	}

	if rd.NewValueKnown("ssl_provider_credentials_id") && rd.Get("ssl_provider_credentials_id").(int) <= 0 {
		return fmt.Errorf("ssl_provider_credentials_id is required for certificate_provider %s", provider)
	}

	return nil
}

// knownString returns the planned value of the passed string attribute and whether it is known at plan time
func knownString(rd *schema.ResourceDiff, key string) (string, bool) {
	if !rd.NewValueKnown(key) {
		return "", false
	}
	return rd.Get(key).(string), true
}

// findRedundantSAN returns the first name that is covered by a wildcard name of the same list
// together with that wildcard. The API drops such names, which would leave a permanent diff
// between configuration and state.
func findRedundantSAN(names []string) (name string, wildcard string) {
	wildcards := make(map[string]struct{})
	for _, n := range names {
		n = normalizeDomainName(n)
		if strings.HasPrefix(n, "*.") {
			wildcards[n[2:]] = struct{}{}
		}
	}

	if len(wildcards) == 0 {
		return "", ""
	}

	for _, n := range names {
		n = normalizeDomainName(n)
		if strings.HasPrefix(n, "*.") {
			continue
		}

		idx := strings.Index(n, ".")
		if idx < 0 {
			continue
		}

		parent := n[idx+1:]
		if _, ok := wildcards[parent]; ok {
			return n, "*." + parent
		}
	}

	return "", ""
}

// resourceMyrasecSSLCertificateRequestCreate ...
func resourceMyrasecSSLCertificateRequestCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	request := buildSSLCertificateRequest(d)

	resp, err := client.CreateSSLCertificateRequest(request)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating SSL certificate request",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(strconv.Itoa(resp.ID))
	setSSLCertificateRequestData(d, resp)

	configurationName := d.Get("configuration_name").(string)
	if configurationName == "" {
		return diags
	}

	// The SSL configuration is stored separately from the request. An error here must not
	// fail the create: the request already exists and an error would taint the resource,
	// the replacement on the next apply deletes the request and its issued certificates.
	// Instead the attribute stays empty in the state, so the next plan shows the pending
	// change and the update applies the configuration.
	d.Set("configuration_name", "")
	resp, err = client.UpdateSSLCertificateRequestConfiguration(resp.ID, configurationName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "SSL configuration not applied to the SSL certificate request",
			Detail:   fmt.Sprintf("The request was created but the SSL configuration [%s] could not be applied, the next apply retries it. %s", configurationName, formatError(err)),
		})
		return diags
	}

	setSSLCertificateRequestData(d, resp)
	d.Set("configuration_name", configurationName)

	return diags
}

// resourceMyrasecSSLCertificateRequestRead ...
func resourceMyrasecSSLCertificateRequestRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics

	requestID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate request ID",
			Detail:   formatError(err),
		})
		return diags
	}

	request, diags := findSSLCertificateRequest(requestID, meta)
	if diags.HasError() {
		return diags
	}

	if request == nil {
		d.SetId("")
		return diags
	}

	setSSLCertificateRequestData(d, request)

	return diags
}

// resourceMyrasecSSLCertificateRequestUpdate ...
func resourceMyrasecSSLCertificateRequestUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	requestID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate request ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating SSL certificate request: %v", requestID)

	if d.HasChangesExcept("configuration_name") {
		// The modified timestamp from the state is the version this plan was built on. The
		// API rejects the update when the request changed in between (optimistic locking).
		modified, err := types.ParseDate(d.Get("modified").(string))
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error parsing modified date of the SSL certificate request",
				Detail:   formatError(err),
			})
			return diags
		}

		// The current version of the request supplies the immutable algorithm and the IDs
		// of the stored subject alternative names. Sending a name with its ID keeps the
		// stored entry, a name without ID replaces it.
		current, err := client.GetSSLCertificateRequest(requestID)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error loading SSL certificate request",
				Detail:   formatError(err),
			})
			return diags
		}

		request := buildSSLCertificateRequest(d)
		request.ID = requestID
		request.Modified = modified
		request.Algorithm = current.Algorithm

		sanIDs := make(map[string]int, len(current.SubjectAlternativeNames))
		for _, san := range current.SubjectAlternativeNames {
			sanIDs[strings.ToLower(san.Name)] = san.ID
		}
		for i, san := range request.SubjectAlternativeNames {
			if id, ok := sanIDs[strings.ToLower(san.Name)]; ok {
				request.SubjectAlternativeNames[i].ID = id
			}
		}

		resp, err := client.UpdateSSLCertificateRequest(request)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Error updating SSL certificate request",
				Detail:   formatError(err),
			})
			return diags
		}

		setSSLCertificateRequestData(d, resp)
	}

	// A removed configuration_name is suppressed by the schema, so a change always
	// carries a name.
	configurationName := d.Get("configuration_name").(string)
	if !d.HasChange("configuration_name") || configurationName == "" {
		return diags
	}

	resp, err := client.UpdateSSLCertificateRequestConfiguration(requestID, configurationName)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error applying SSL configuration to the SSL certificate request",
			Detail:   formatError(err),
		})
		return diags
	}

	setSSLCertificateRequestData(d, resp)

	return diags
}

// resourceMyrasecSSLCertificateRequestDelete ...
func resourceMyrasecSSLCertificateRequestDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	requestID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL certificate request ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting SSL certificate request: %v", requestID)

	_, err = client.DeleteSSLCertificateRequest(&myrasec.SSLCertificateRequest{ID: requestID})
	if err != nil {
		if isNotFoundError(err) {
			return diags
		}
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting SSL certificate request",
			Detail:   formatError(err),
		})
		return diags
	}

	return diags
}

// resourceMyrasecSSLCertificateRequestImport ...
func resourceMyrasecSSLCertificateRequestImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	requestID, err := strconv.Atoi(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing SSL certificate request ID: [%s]", err.Error())
	}

	request, diags := findSSLCertificateRequest(requestID, meta)
	if diags.HasError() || request == nil {
		return nil, fmt.Errorf("unable to find SSL certificate request with ID = [%d]", requestID)
	}

	d.SetId(strconv.Itoa(requestID))
	setSSLCertificateRequestData(d, request)

	return []*schema.ResourceData{d}, nil
}

// buildSSLCertificateRequest builds the request from the state. The ID, the modified
// timestamp and the IDs of the nested objects are not set, updates add them from the API.
func buildSSLCertificateRequest(d *schema.ResourceData) *myrasec.SSLCertificateRequest {
	request := &myrasec.SSLCertificateRequest{
		Provider:                 d.Get("certificate_provider").(string),
		Algorithm:                d.Get("algorithm").(string),
		SSLProviderCredentialsID: d.Get("ssl_provider_credentials_id").(int),
		RenewalInterval:          d.Get("renewal_interval").(int),
		SignatureAlgorithm:       d.Get("signature_algorithm").(string),
		SubjectAlternativeNames:  []myrasec.SSLCertificateRequestSAN{},
		Assignments:              []myrasec.SSLCertificateRequestAssignment{},
	}

	for _, name := range expandStringSet(d.Get("subject_alternative_names")) {
		request.SubjectAlternativeNames = append(request.SubjectAlternativeNames, myrasec.SSLCertificateRequestSAN{Name: name})
	}

	for _, subDomainName := range expandStringSet(d.Get("subdomains")) {
		request.Assignments = append(request.Assignments, myrasec.SSLCertificateRequestAssignment{SubDomainName: subDomainName})
	}

	return request
}

// findSSLCertificateRequest returns the request with the passed ID or nil when it does not exist
func findSSLCertificateRequest(requestID int, meta any) (*myrasec.SSLCertificateRequest, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	request, err := client.GetSSLCertificateRequest(requestID)
	if err != nil {
		if isNotFoundError(err) {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Unable to find SSL certificate request",
				Detail:   fmt.Sprintf("Unable to find SSL certificate request with ID = [%d]", requestID),
			})
			return nil, diags
		}

		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error loading SSL certificate request",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	return request, diags
}

// setSSLCertificateRequestData writes the API response to the state.
// configuration_name is not part of the request object and keeps its configured value.
func setSSLCertificateRequestData(d *schema.ResourceData, request *myrasec.SSLCertificateRequest) {
	names := make([]string, 0, len(request.SubjectAlternativeNames))
	for _, san := range request.SubjectAlternativeNames {
		names = append(names, san.Name)
	}

	subdomains := make([]string, 0, len(request.Assignments))
	for _, assignment := range request.Assignments {
		subdomains = append(subdomains, assignment.SubDomainName)
	}

	d.SetId(strconv.Itoa(request.ID))
	d.Set("request_id", request.ID)
	d.Set("created", formatDateTime(request.Created))
	d.Set("modified", formatDateTime(request.Modified))
	d.Set("certificate_provider", request.Provider)
	d.Set("algorithm", request.Algorithm)
	d.Set("subject_alternative_names", names)
	d.Set("subdomains", subdomains)
	d.Set("ssl_provider_credentials_id", request.SSLProviderCredentialsID)
	d.Set("renewal_interval", request.RenewalInterval)
	d.Set("signature_algorithm", request.SignatureAlgorithm)
	d.Set("status", request.Status)
	d.Set("failure_reason", request.FailureReason)
	d.Set("customer_actionable", request.CustomerActionable)
	d.Set("multi_domain", request.MultiDomain)
}
