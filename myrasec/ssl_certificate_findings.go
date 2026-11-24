package myrasec

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
)

var sslIntermediatePathPattern = regexp.MustCompile(`^intermediates\[(\d+)\]`)

// sslCertificateFinding is one violation or warning of the API's certificate check, located on the
// Terraform attribute it belongs to.
type sslCertificateFinding struct {
	attribute string
	label     string
}

// locateSSLCertificateFinding maps a field path of the API (cert, key, intermediates,
// intermediates[n].cert) to the Terraform attribute. intermediate is a set, so the n of the API is
// the order the provider sent the blocks in, not the order of the configuration: the label names the
// sent intermediate by its subject instead.
func locateSSLCertificateFinding(path string, parameters map[string]any, sent []myrasec.SSLIntermediate) sslCertificateFinding {
	switch path {
	case "":
		return sslCertificateFinding{}
	case "cert":
		return sslCertificateFinding{attribute: "certificate", label: "certificate"}
	case "key":
		return sslCertificateFinding{attribute: "key", label: "key"}
	case "intermediates":
		return sslCertificateFinding{attribute: "intermediate", label: "intermediate"}
	}

	match := sslIntermediatePathPattern.FindStringSubmatch(path)
	if match == nil {
		return sslCertificateFinding{label: path}
	}

	index, _ := strconv.Atoi(match[1])
	subject := sentIntermediateSubject(index, sent)
	if subject == "" {
		if s, ok := parameters["subject"].(string); ok {
			subject = s
		}
	}
	if subject == "" {
		return sslCertificateFinding{attribute: "intermediate", label: fmt.Sprintf("intermediate %d", index+1)}
	}

	return sslCertificateFinding{attribute: "intermediate", label: fmt.Sprintf("intermediate %q", subject)}
}

func sentIntermediateSubject(index int, sent []myrasec.SSLIntermediate) string {
	if index < 0 || index >= len(sent) || sent[index].Certificate == nil {
		return ""
	}

	block, _ := pem.Decode([]byte(sent[index].Cert))
	if block == nil {
		return ""
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}

	return parsed.Subject.String()
}

func (f sslCertificateFinding) diagnostic(severity diag.Severity, summary, message, code string) diag.Diagnostic {
	detail := message
	if f.label != "" {
		detail = f.label + ": " + detail
	}
	if code != "" {
		detail += " [" + code + "]"
	}

	d := diag.Diagnostic{Severity: severity, Summary: summary, Detail: detail}
	if f.attribute != "" {
		d.AttributePath = cty.GetAttrPath(f.attribute)
	}

	return d
}

// sslCertificateSaveErrorDiagnostics reports a rejected save with one error per blocking result of
// the API, on the Terraform attribute it belongs to, followed by the warnings of the same check.
// Other errors keep the plain error text.
func sslCertificateSaveErrorDiagnostics(summary string, err error, sent []myrasec.SSLIntermediate) diag.Diagnostics {
	var apiErr *myrasec.APIError
	if !errors.As(err, &apiErr) || len(apiErr.Violations) == 0 {
		return diag.Diagnostics{{Severity: diag.Error, Summary: summary, Detail: formatError(err)}}
	}

	var diags diag.Diagnostics
	for _, v := range apiErr.Violations {
		diags = append(diags, locateSSLCertificateFinding(v.Path, v.Parameters, sent).diagnostic(diag.Error, summary, v.Message, v.Code))
	}
	if apiErr.ErrorMessage != "" {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Summary: summary, Detail: apiErr.ErrorMessage})
	}

	return append(diags, sslCertificateWarningDiagnostics("SSL certificate check warning", apiErr.Warnings, sent)...)
}

// sslCertificateWarningDiagnostics turns the warnings the API returned next to a save into warning
// diagnostics. They do not fail the apply and appear only on the apply that sent the material.
func sslCertificateWarningDiagnostics(summary string, warnings []*myrasec.Warning, sent []myrasec.SSLIntermediate) diag.Diagnostics {
	var diags diag.Diagnostics
	for _, w := range warnings {
		diags = append(diags, locateSSLCertificateFinding(w.Path, w.Parameters, sent).diagnostic(diag.Warning, summary, w.Message, w.Code))
	}

	return diags
}
