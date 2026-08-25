//go:build server

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
)

// Trusted external issuers are defined in configuration
// (Origin.Exports[*].ExternalIssuers / Issuer.ExternalIssuers), not the
// database, so this CLI is read-only: list what is configured and run the
// probe / dry-run diagnostics. To change which issuers are trusted, edit the
// configuration and restart, like any other config change.
var (
	originIssuerExtCmd = &cobra.Command{
		Use:   "external-issuer",
		Short: "Inspect trusted external issuers for token exchange (read-only)",
		Long: `Inspect the external OAuth2/OIDC issuers this origin's embedded issuer will accept
as the subject_token of an RFC 8693 token exchange.

Trusted external issuers are defined in configuration
(Origin.Exports[*].ExternalIssuers or the global Issuer.ExternalIssuers), not
here — they are trust anchors and belong under change control. This command
lists what is configured and offers two diagnostics: probe (fetch the issuer's
discovery document and keys now) and dry-run (evaluate a sample token through
the real decision path without issuing anything).

A client must additionally be blessed for external exchange with
  pelican-server origin issuer client update --id <client> --allow-external-exchange`,
	}

	extIssuerName         string
	extIssuerTokenFile    string
	extIssuerDryRunClient string

	originIssuerExtListCmd = &cobra.Command{
		Use:   "list",
		Short: "List the trusted external issuers configured for this namespace",
		RunE:  extIssuerListRun,
	}

	originIssuerExtProbeCmd = &cobra.Command{
		Use:   "probe",
		Short: "Fetch an external issuer's discovery document and JWKS now",
		Long: `Perform OIDC discovery and fetch the issuer's key set immediately, reporting how
many keys were found and which algorithms they use. Use it to confirm
connectivity and configuration without producing a token.`,
		RunE: extIssuerProbeRun,
	}

	originIssuerExtDryRunCmd = &cobra.Command{
		Use:   "dry-run",
		Short: "Evaluate a sample subject token without issuing anything",
		Long: `Run a sample external access token through the real token-exchange decision path
and report what would happen — whether it verifies, which Pelican user it maps
to (or would enroll as), which groups it yields, and which scopes it would be
granted. Nothing is minted and no state changes.

Example:
  pelican-server origin issuer external-issuer dry-run --server https://my-origin:8447 \
    --namespace /project --name keycloak --token-file ./keycloak-access-token.jwt`,
		RunE: extIssuerDryRunRun,
	}
)

func init() {
	originIssuerCmd.AddCommand(originIssuerExtCmd)

	originIssuerExtCmd.PersistentFlags().StringVar(&issuerClientServerURL, "server", "", "Web URL of the Pelican origin server (e.g. https://my-origin:8447)")
	originIssuerExtCmd.PersistentFlags().StringVar(&issuerClientTokenPath, "token", "", "Path to a file containing an admin token (optional; generated automatically if omitted)")
	originIssuerExtCmd.PersistentFlags().StringVar(&issuerClientNamespace, "namespace", "", "Federation namespace prefix for the issuer (e.g. /data/analysis) (required)")
	if err := originIssuerExtCmd.MarkPersistentFlagRequired("namespace"); err != nil {
		log.Errorln("Failed to mark namespace flag as required:", err)
	}

	originIssuerExtCmd.AddCommand(originIssuerExtListCmd)

	for _, c := range []*cobra.Command{originIssuerExtProbeCmd, originIssuerExtDryRunCmd} {
		c.Flags().StringVar(&extIssuerName, "name", "", "Configured external issuer name (required)")
		if err := c.MarkFlagRequired("name"); err != nil {
			log.Errorln("Failed to mark name flag as required:", err)
		}
		originIssuerExtCmd.AddCommand(c)
	}

	originIssuerExtDryRunCmd.Flags().StringVar(&extIssuerTokenFile, "token-file", "", "File containing a sample external access token (required)")
	originIssuerExtDryRunCmd.Flags().StringVar(&extIssuerDryRunClient, "client-id", "", "Evaluate against this client's scope allow-list")
	if err := originIssuerExtDryRunCmd.MarkFlagRequired("token-file"); err != nil {
		log.Errorln("Failed to mark token-file flag as required:", err)
	}
}

// externalIssuerAPIPath returns the read-only admin API path for external
// issuers, optionally addressing one by name and a sub-action.
func externalIssuerAPIPath(name, sub string) string {
	p := "/api/v1.0/issuer/admin/ns" + issuerClientNamespace + "/external-issuers"
	if name != "" {
		p += "/" + name
	}
	if sub != "" {
		p += "/" + sub
	}
	return p
}

func issuerAdminRequest(ctx context.Context, method, apiPath string, payload interface{}) ([]byte, error) {
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}
	targetURL, err := constructIssuerAdminURL(issuerClientServerURL, apiPath)
	if err != nil {
		return nil, err
	}
	var body *bytes.Buffer
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to marshal request payload")
		}
		body = bytes.NewBuffer(encoded)
	} else {
		body = bytes.NewBuffer(nil)
	}
	tok, err := fetchOrGenerateWebAPIAdminToken(issuerClientServerURL, issuerClientTokenPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL.String(), body)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create HTTP request")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Accept", "application/json")
	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()
	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		return nil, errors.Wrap(err, "Server request failed")
	}
	return bodyBytes, nil
}

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func jsonRequested(cmd *cobra.Command) bool {
	jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json")
	return jsonFlag
}

func printJSON(bodyBytes []byte) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, bodyBytes, "", "  "); err == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(bodyBytes))
	}
}

func printExternalIssuer(rec map[string]interface{}) {
	fmt.Printf("Name:              %v\n", rec["name"])
	fmt.Printf("Issuer URL:        %v\n", rec["issuer_url"])
	if jwks, ok := rec["jwks_url"]; ok && jwks != "" {
		fmt.Printf("JWKS URL:          %v\n", jwks)
	}
	fmt.Printf("Enabled:           %v\n", rec["enabled"])
	if allowAny, _ := rec["allow_any_audience"].(bool); allowAny {
		fmt.Printf("Required audience: (ANY — accepts tokens minted for any audience)\n")
	} else {
		fmt.Printf("Required audience: %v\n", rec["required_audiences"])
	}
	if scopes, ok := rec["required_scopes"]; ok {
		fmt.Printf("Required scopes:   %v\n", scopes)
	}
	if claims, ok := rec["required_claims"]; ok {
		fmt.Printf("Required claims:   %v\n", claims)
	}
	fmt.Printf("Subject claim:     %v\n", rec["subject_claim"])
	fmt.Printf("Auto-enroll:       %v\n", rec["auto_enroll"])
	fmt.Printf("Group mode:        %v\n", rec["group_mode"])
	prefix, _ := rec["group_prefix"].(string)
	if prefix == "" {
		fmt.Printf("Group prefix:      (none — external group names are used unchanged)\n")
	} else {
		fmt.Printf("Group prefix:      %s\n", prefix)
	}
	if maps, ok := rec["group_mappings"]; ok && maps != nil {
		fmt.Printf("Group mappings:    %v\n", maps)
	}
	fmt.Printf("Local groups:      %v\n", rec["include_local_groups"])
	fmt.Printf("Allow refresh:     %v\n", rec["allow_refresh"])
}

func extIssuerListRun(cmd *cobra.Command, args []string) error {
	bodyBytes, err := issuerAdminRequest(cmdContext(cmd), "GET", externalIssuerAPIPath("", ""), nil)
	if err != nil {
		return err
	}
	if jsonRequested(cmd) {
		printJSON(bodyBytes)
		return nil
	}
	var records []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &records); err != nil {
		fmt.Println(string(bodyBytes))
		return nil
	}
	if len(records) == 0 {
		fmt.Println("No trusted external issuers are configured for this namespace.")
		return nil
	}
	for i, rec := range records {
		if i > 0 {
			fmt.Println()
		}
		printExternalIssuer(rec)
	}
	return nil
}

func extIssuerProbeRun(cmd *cobra.Command, args []string) error {
	bodyBytes, err := issuerAdminRequest(cmdContext(cmd), "POST", externalIssuerAPIPath(extIssuerName, "probe"), map[string]interface{}{})
	if err != nil {
		return err
	}
	if jsonRequested(cmd) {
		printJSON(bodyBytes)
		return nil
	}
	var rec map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rec); err != nil {
		fmt.Println(string(bodyBytes))
		return nil
	}
	if ok, _ := rec["ok"].(bool); !ok {
		fmt.Printf("Probe FAILED for %v\n  %v\n", rec["issuer_url"], rec["error"])
		return errors.New("probe failed")
	}
	fmt.Printf("Probe OK\n")
	fmt.Printf("  Issuer URL:  %v\n", rec["issuer_url"])
	fmt.Printf("  JWKS URL:    %v\n", rec["jwks_url"])
	fmt.Printf("  Keys:        %v\n", rec["key_count"])
	if kids, ok := rec["key_ids"]; ok {
		fmt.Printf("  Key IDs:     %v\n", kids)
	}
	if algs, ok := rec["algorithms"]; ok {
		fmt.Printf("  Algorithms:  %v\n", algs)
	}
	return nil
}

func extIssuerDryRunRun(cmd *cobra.Command, args []string) error {
	tokenBytes, err := os.ReadFile(extIssuerTokenFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read the sample token from %s", extIssuerTokenFile)
	}
	payload := map[string]interface{}{"subject_token": strings.TrimSpace(string(tokenBytes))}
	if extIssuerDryRunClient != "" {
		payload["client_id"] = extIssuerDryRunClient
	}
	bodyBytes, err := issuerAdminRequest(cmdContext(cmd), "POST", externalIssuerAPIPath(extIssuerName, "dry-run"), payload)
	if err != nil {
		return err
	}
	if jsonRequested(cmd) {
		printJSON(bodyBytes)
		return nil
	}
	var rec map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rec); err != nil {
		fmt.Println(string(bodyBytes))
		return nil
	}
	if ok, _ := rec["ok"].(bool); !ok {
		fmt.Printf("This token would be REFUSED:\n  %v\n", rec["error"])
		return errors.New("dry run rejected the token")
	}
	fmt.Printf("This token would be ACCEPTED.\n\n")
	fmt.Printf("  External issuer:  %v\n", rec["external_issuer"])
	fmt.Printf("  External subject: %v\n", rec["external_subject"])
	if enroll, _ := rec["would_enroll"].(bool); enroll {
		fmt.Printf("  Pelican user:     %v (would be CREATED — no account is linked yet)\n", rec["username"])
	} else {
		fmt.Printf("  Pelican user:     %v (%v)\n", rec["username"], rec["user_id"])
	}
	fmt.Printf("  Groups:           %v\n", rec["groups"])
	fmt.Printf("  Granted scopes:   %v\n", rec["granted_scopes"])
	fmt.Printf("  Token lifetime:   %v seconds\n", rec["lifetime_seconds"])
	return nil
}
