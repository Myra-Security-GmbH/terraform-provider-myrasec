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

// resourceMyrasecSSLProviderCredentials ...
func resourceMyrasecSSLProviderCredentials() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecSSLProviderCredentialsCreate,
		ReadContext:   resourceMyrasecSSLProviderCredentialsRead,
		UpdateContext: resourceMyrasecSSLProviderCredentialsUpdate,
		DeleteContext: resourceMyrasecSSLProviderCredentialsDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecSSLProviderCredentialsImport,
		},
		Schema: map[string]*schema.Schema{
			"credentials_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the SSL provider credentials.",
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
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "User-defined label for the credentials.",
				ValidateFunc: validateNotBlank,
			},
			"certificate_provider": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "The certificate provider the credentials belong to. Valid values: SECTIGO, DTRUST. The EAB credentials are issued by one provider, a change replaces the credentials.",
				ValidateFunc: validation.StringInSlice([]string{myrasec.SSLProviderSectigo, myrasec.SSLProviderDTrust}, false),
			},
			"cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Public certificate of the ACME account key pair (PEM). Leave cert and private_key empty to let the server generate a key pair.",
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return strings.TrimSpace(oldValue) == strings.TrimSpace(newValue)
				},
			},
			"private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Private key of the ACME account key pair (PEM). Write-only: the API never returns it and discards changes after creation.",
			},
			"email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Contact email address of the provider account. Optional for SECTIGO, must be empty for DTRUST.",
			},
			"endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ACME directory URL of the provider product, e.g. https://acme.sectigo.com/v2/OV. Required for SECTIGO, optional for DTRUST.",
				// D-Trust falls back to a platform default the API may return, an omitted
				// endpoint keeps the stored one.
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return newValue == ""
				},
			},
			"eab_kid": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "External Account Binding (EAB) key identifier issued by the provider.",
				ValidateFunc: validateNotBlank,
			},
			"eab_hmac": {
				Type:         schema.TypeString,
				Required:     true,
				Sensitive:    true,
				Description:  "External Account Binding (EAB) HMAC key issued by the provider. Write-only: the API never returns it. A changed value rotates the stored key.",
				ValidateFunc: validateNotBlank,
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional free-text note.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
		CustomizeDiff: func(ctx context.Context, rd *schema.ResourceDiff, i any) error {
			return validateSSLProviderCredentialsDiff(rd)
		},
	}
}

// validateSSLProviderCredentialsDiff checks the provider specific constraints of the credentials
func validateSSLProviderCredentialsDiff(rd *schema.ResourceDiff) error {
	provider := rd.Get("certificate_provider").(string)
	email := rd.Get("email").(string)
	endpoint := rd.Get("endpoint").(string)

	if provider == myrasec.SSLProviderDTrust && email != "" {
		return errors.New("email must be empty for certificate_provider DTRUST")
	}

	if provider == myrasec.SSLProviderSectigo && rd.NewValueKnown("endpoint") && endpoint == "" {
		return errors.New("endpoint is required for certificate_provider SECTIGO")
	}

	// The key pair can only be supplied on creation. On updates cert is a computed value
	// from the API while private_key is never returned, so the pair check is not possible.
	if rd.Id() != "" {
		return nil
	}

	cert := rd.Get("cert").(string)
	privateKey := rd.Get("private_key").(string)
	if (cert == "") != (privateKey == "") {
		return errors.New("cert and private_key have to be set together or both left empty")
	}

	return nil
}

// resourceMyrasecSSLProviderCredentialsCreate ...
func resourceMyrasecSSLProviderCredentialsCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	credentials, err := buildSSLProviderCredentials(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL provider credentials",
			Detail:   formatError(err),
		})
		return diags
	}

	resp, err := client.CreateSSLProviderCredentials(credentials)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating SSL provider credentials",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(strconv.Itoa(resp.ID))
	setSSLProviderCredentialsData(d, resp)

	return diags
}

// resourceMyrasecSSLProviderCredentialsRead ...
func resourceMyrasecSSLProviderCredentialsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics

	credentialsID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL provider credentials ID",
			Detail:   formatError(err),
		})
		return diags
	}

	credentials, diags := findSSLProviderCredentials(credentialsID, meta)
	if diags.HasError() {
		return diags
	}

	if credentials == nil {
		d.SetId("")
		return diags
	}

	setSSLProviderCredentialsData(d, credentials)

	return diags
}

// resourceMyrasecSSLProviderCredentialsUpdate ...
func resourceMyrasecSSLProviderCredentialsUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	credentialsID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL provider credentials ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating SSL provider credentials: %v", credentialsID)

	credentials, err := buildSSLProviderCredentials(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building SSL provider credentials",
			Detail:   formatError(err),
		})
		return diags
	}

	// The secrets are write-only. An empty eab_hmac keeps the stored one, so it is only
	// sent when it changed in the configuration. The private key cannot be replaced after
	// creation at all and is never sent on updates.
	if !d.HasChange("eab_hmac") {
		credentials.EABHmac = ""
	}

	credentials.PrivateKey = ""
	if d.HasChange("private_key") {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Changed private_key is not applied",
			Detail:   "The private key of the ACME account key pair cannot be replaced after creation. Contact Myra support to replace the key pair.",
		})
	}

	resp, err := client.UpdateSSLProviderCredentials(credentials)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error updating SSL provider credentials",
			Detail:   formatError(err),
		})
		return diags
	}

	setSSLProviderCredentialsData(d, resp)

	return diags
}

// resourceMyrasecSSLProviderCredentialsDelete ...
func resourceMyrasecSSLProviderCredentialsDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	credentialsID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing SSL provider credentials ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting SSL provider credentials: %v", credentialsID)

	_, err = client.DeleteSSLProviderCredentials(&myrasec.SSLProviderCredentials{ID: credentialsID})
	if err != nil {
		if isNotFoundError(err) {
			return diags
		}
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting SSL provider credentials",
			Detail:   formatError(err),
		})
		return diags
	}

	return diags
}

// resourceMyrasecSSLProviderCredentialsImport ...
func resourceMyrasecSSLProviderCredentialsImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	credentialsID, err := strconv.Atoi(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing SSL provider credentials ID: [%s]", err.Error())
	}

	credentials, diags := findSSLProviderCredentials(credentialsID, meta)
	if diags.HasError() || credentials == nil {
		return nil, fmt.Errorf("unable to find SSL provider credentials with ID = [%d]", credentialsID)
	}

	d.SetId(strconv.Itoa(credentialsID))
	setSSLProviderCredentialsData(d, credentials)

	return []*schema.ResourceData{d}, nil
}

// buildSSLProviderCredentials ...
func buildSSLProviderCredentials(d *schema.ResourceData) (*myrasec.SSLProviderCredentials, error) {
	credentials := &myrasec.SSLProviderCredentials{
		Name:       d.Get("name").(string),
		Provider:   d.Get("certificate_provider").(string),
		Cert:       d.Get("cert").(string),
		PrivateKey: d.Get("private_key").(string),
		Email:      d.Get("email").(string),
		Endpoint:   d.Get("endpoint").(string),
		EABKid:     d.Get("eab_kid").(string),
		EABHmac:    d.Get("eab_hmac").(string),
		Comment:    d.Get("comment").(string),
	}

	if d.Get("credentials_id").(int) > 0 {
		credentials.ID = d.Get("credentials_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			credentials.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	credentials.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	credentials.Modified = modified

	return credentials, nil
}

// findSSLProviderCredentials returns the credentials with the passed ID or nil when they do not exist
func findSSLProviderCredentials(credentialsID int, meta any) (*myrasec.SSLProviderCredentials, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	credentials, err := client.GetSSLProviderCredentials(credentialsID)
	if err != nil {
		if isNotFoundError(err) {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Unable to find SSL provider credentials",
				Detail:   fmt.Sprintf("Unable to find SSL provider credentials with ID = [%d]", credentialsID),
			})
			return nil, diags
		}

		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error loading SSL provider credentials",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	return credentials, diags
}

// setSSLProviderCredentialsData writes the API response to the state.
// eab_hmac and private_key are write-only and never returned by the API, the configured values are kept.
func setSSLProviderCredentialsData(d *schema.ResourceData, credentials *myrasec.SSLProviderCredentials) {
	d.SetId(strconv.Itoa(credentials.ID))
	d.Set("credentials_id", credentials.ID)
	d.Set("created", formatDateTime(credentials.Created))
	d.Set("modified", formatDateTime(credentials.Modified))
	d.Set("name", credentials.Name)
	d.Set("certificate_provider", credentials.Provider)
	d.Set("cert", credentials.Cert)
	d.Set("email", credentials.Email)
	d.Set("endpoint", credentials.Endpoint)
	d.Set("eab_kid", credentials.EABKid)
	d.Set("comment", credentials.Comment)
}
