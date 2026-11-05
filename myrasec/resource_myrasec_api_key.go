package myrasec

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/Myra-Security-GmbH/myrasec-go/v2/pkg/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// resourceMyrasecApiKey ...
func resourceMyrasecApiKey() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceMyrasecApiKeyCreate,
		ReadContext:   resourceMyrasecApiKeyRead,
		UpdateContext: resourceMyrasecApiKeyUpdate,
		DeleteContext: resourceMyrasecApiKeyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceMyrasecApiKeyImport,
		},
		Schema: map[string]*schema.Schema{
			"key_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "ID of the API key.",
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
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the API key.",
			},
			"key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The API key.",
			},
			"secret": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The secret part of the API key.",
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Second),
			Update: schema.DefaultTimeout(30 * time.Second),
		},
	}
}

// resourceMyrasecApiKeyCreate ...
func resourceMyrasecApiKeyCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	key, err := buildApiKey(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building API key",
			Detail:   formatError(err),
		})
		return diags
	}

	key, err = client.CreateApiKey(key)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error creating API key",
			Detail:   formatError(err),
		})
		return diags
	}

	d.SetId(fmt.Sprintf("%d", key.ID))
	setApiKeyData(d, key)
	return diags
}

// resourceMyrasecApiKeyRead ...
func resourceMyrasecApiKeyRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	var key *myrasec.APIKey

	keyID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing API key ID",
			Detail:   formatError(err),
		})
		return diags
	}

	key, diags = findApiKey(keyID, meta)

	if diags.HasError() {
		return diags
	}

	if key == nil {
		d.SetId("")
		return nil
	}

	setApiKeyData(d, key)

	return diags
}

// resourceMyrasecApiKeyUpdate ...
func resourceMyrasecApiKeyUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics

	keyID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing API key ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating API key: %v", keyID)

	_, err = buildApiKey(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building API key",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Updating API key is not supported. Won't change anything...")

	return diags
}

// resourceMyrasecApiKeyDelete ...
func resourceMyrasecApiKeyDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*myrasec.API)

	var diags diag.Diagnostics

	keyID, err := strconv.Atoi(d.Id())
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error parsing API key ID",
			Detail:   formatError(err),
		})
		return diags
	}

	log.Printf("[INFO] Deleting API key: %v", keyID)

	key, err := buildApiKey(d)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error building API key",
			Detail:   formatError(err),
		})
		return diags
	}

	_, err = client.DeleteApiKey(key)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error deleting API key",
			Detail:   formatError(err),
		})
		return diags
	}
	return diags
}

// resourceMyrasecApiKeyImport ...
func resourceMyrasecApiKeyImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	name, keyID, err := parseResourceServiceID(d.Id())
	if err != nil {
		return nil, fmt.Errorf("error parsing API key ID: [%s]", err.Error())
	}

	key, diags := findApiKey(keyID, meta)
	if diags.HasError() {
		return nil, diagnosticsError(diags)
	}
	if key == nil {
		return nil, fmt.Errorf("unable to find API key with ID = [%d]", keyID)
	}

	d.SetId(strconv.Itoa(keyID))
	if err := d.Set("key_id", key.ID); err != nil {
		return nil, err
	}
	if err := d.Set("name", name); err != nil {
		return nil, err
	}
	return finishImport(ctx, d, meta, resourceMyrasecApiKeyRead)
}

// buildApiKey ...
func buildApiKey(d *schema.ResourceData) (*myrasec.APIKey, error) {
	key := &myrasec.APIKey{
		Name:   d.Get("name").(string),
		Key:    d.Get("key").(string),
		Secret: d.Get("secret").(string),
	}

	if d.Get("key_id").(int) > 0 {
		key.ID = d.Get("key_id").(int)
	} else {
		id, err := strconv.Atoi(d.Id())
		if err == nil && id > 0 {
			key.ID = id
		}
	}

	created, err := types.ParseDate(d.Get("created").(string))
	if err != nil {
		return nil, err
	}
	key.Created = created

	modified, err := types.ParseDate(d.Get("modified").(string))
	if err != nil {
		return nil, err
	}
	key.Modified = modified

	return key, nil
}

// findApiKey ...
func findApiKey(keyID int, meta any) (*myrasec.APIKey, diag.Diagnostics) {
	var diags diag.Diagnostics

	client := meta.(*myrasec.API)

	params := map[string]string{}

	found, err := findInPages(params, func(row myrasec.APIKey) int { return row.ID }, client.ListApiKeys, func(row myrasec.APIKey) bool { return row.ID == keyID })
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Error loading API keys",
			Detail:   formatError(err),
		})
		return nil, diags
	}

	if found != nil {
		return found, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Unable to find API key",
		Detail:   fmt.Sprintf("Unable to find API key with ID = [%d]", keyID),
	})
	return nil, diags
}

// setApiKeyData ...
func setApiKeyData(d *schema.ResourceData, key *myrasec.APIKey) {
	d.SetId(strconv.Itoa(key.ID))
	d.Set("key_id", key.ID)
	d.Set("created", key.Created.Format(time.RFC3339))
	d.Set("modified", key.Modified.Format(time.RFC3339))
	d.Set("name", key.Name)
	d.Set("key", key.Key)
	// The API returns the secret only in the create response, a read must not overwrite
	// the stored value with an empty string.
	if key.Secret != "" {
		d.Set("secret", key.Secret)
	}
}
