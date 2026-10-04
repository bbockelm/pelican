/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package config

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type OauthIssuer struct {
	Issuer          string   `json:"issuer"`
	JwksUri         string   `json:"jwks_uri"`
	AuthURL         string   `json:"authorization_endpoint"`
	DeviceAuthURL   string   `json:"device_authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	RegistrationURL string   `json:"registration_endpoint"`
	UserInfoURL     string   `json:"userinfo_endpoint"`
	GrantTypes      []string `json:"grant_types_supported"`
	ScopesSupported []string `json:"scopes_supported"`

	// TokenEndpointAuthMethods lists the client authentication methods the
	// token endpoint accepts (RFC 8414 token_endpoint_auth_methods_supported).
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`

	// ClientIDMetadataDocumentSupported reports whether the authorization
	// server accepts an HTTPS URL as a client_id and fetches the client's
	// metadata from it (draft-ietf-oauth-client-id-metadata-document).
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported"`

	// TokenEndpointAuthSigningAlgs lists the JWS algorithms the token
	// endpoint accepts for private_key_jwt client assertions (RFC 8414).
	TokenEndpointAuthSigningAlgs []string `json:"token_endpoint_auth_signing_alg_values_supported"`
}

// Get OIDC issuer metadata from an OIDC issuer URL.
// The URL should not contain the path to /.well-known/openid-configuration
func GetIssuerMetadata(issuer_url string) (*OauthIssuer, error) {
	return GetIssuerMetadataWithClient(issuer_url, &http.Client{Transport: GetTransport()})
}

// GetIssuerMetadataWithClient is like GetIssuerMetadata but uses the provided
// HTTP client.  Server-side callers that fetch a metadata document from a
// user-supplied issuer URL should pass a client backed by the SSRF-resistant
// transport (config.GetSSRFHttpTransport) so the fetch cannot be used to reach
// non-publicly-routable addresses.
func GetIssuerMetadataWithClient(issuer_url string, client *http.Client) (*OauthIssuer, error) {
	wellKnownUrl := strings.TrimSuffix(issuer_url, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequest(http.MethodGet, wellKnownUrl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.Errorf("Failed to retrieve issuer metadata at %s with status code %d", wellKnownUrl, resp.StatusCode)
	}

	issuer := &OauthIssuer{}
	err = json.Unmarshal(body, issuer)
	return issuer, err
}

// GetAuthServerMetadata discovers an authorization server's metadata the way
// RFC 8414 describes, honoring ctx and checking that the document describes
// the issuer that was asked about.
//
// The OpenID Connect location (<issuer>/.well-known/openid-configuration) is
// tried first because every issuer Pelican has historically talked to serves
// it; a server that is only an OAuth 2.0 authorization server is then looked
// up at the RFC 8414 location, where the well-known segment is inserted
// between the host and the issuer's path.
//
// The returned metadata's issuer must equal issuerURL (ignoring a trailing
// slash).  RFC 8414 section 3.3 requires that check: without it, a document
// fetched from one server could steer the caller's tokens and client
// credentials to the endpoints of another.
func GetAuthServerMetadata(ctx context.Context, issuerURL string, client *http.Client) (*OauthIssuer, error) {
	parsed, err := url.Parse(issuerURL)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid issuer URL %q", issuerURL)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.Errorf("invalid issuer URL %q: scheme and host are required", issuerURL)
	}

	oidcURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	rfc8414 := *parsed
	rfc8414.Path = "/.well-known/oauth-authorization-server" + strings.TrimSuffix(parsed.Path, "/")
	rfc8414.RawPath = ""
	rfc8414.RawQuery = ""
	rfc8414.Fragment = ""

	var firstErr error
	for _, candidate := range []string{oidcURL, rfc8414.String()} {
		md, err := fetchAuthServerMetadata(ctx, candidate, client)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if strings.TrimSuffix(md.Issuer, "/") != strings.TrimSuffix(issuerURL, "/") {
			return nil, errors.Errorf("authorization server metadata at %s names issuer %q, not the expected %q", candidate, md.Issuer, issuerURL)
		}
		return md, nil
	}
	return nil, errors.Wrapf(firstErr, "failed to discover authorization server metadata for %s", issuerURL)
}

func fetchAuthServerMetadata(ctx context.Context, metadataURL string, client *http.Client) (*OauthIssuer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to retrieve authorization server metadata at %s: status code %d", metadataURL, resp.StatusCode)
	}
	md := &OauthIssuer{}
	if err := json.Unmarshal(body, md); err != nil {
		return nil, errors.Wrapf(err, "invalid authorization server metadata at %s", metadataURL)
	}
	return md, nil
}
