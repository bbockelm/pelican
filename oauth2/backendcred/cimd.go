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

package backendcred

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/version"
)

// ClientIDMetadataDocumentPath is where, under a director's base URL, the
// director serves OAuth client ID metadata documents for the federation's
// servers.  The server's registry prefix (/caches/<name> or
// /origins/<host>) follows it.
const ClientIDMetadataDocumentPath = "/api/v1.0/director/oauthClients"

// ClientIDMetadataDocument is the client metadata a Pelican director publishes
// for one of the federation's servers, at the URL that serves as that server's
// OAuth client_id (draft-ietf-oauth-client-id-metadata-document).
//
// The document describes a confidential client that authenticates with
// private_key_jwt using the keys the server registered with the federation
// registry, so:
//
//   - an issuer can tell the federation's servers apart (each has its own
//     client_id),
//   - a refresh token issued to a server is useless without that server's
//     private key, and
//   - the federation, not each site, vouches for the client: the document
//     lives on the director's host, and the keys it points to are served by
//     the registry only for registered (and, where the federation requires
//     it, approved) servers.
//
// The device authorization grant has no redirect, so the document carries
// no redirect_uris.
type ClientIDMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	JWKSURI                 string   `json:"jwks_uri"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

const (
	authMethodPrivateKeyJWT = "private_key_jwt"
	authMethodSecretBasic   = "client_secret_basic"
	authMethodNone          = "none"

	pelicanSoftwareID = "https://pelicanplatform.org"
)

// A registry server name: a site name or a host[:port], a single path segment.
var serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// validateServerPrefix accepts exactly /caches/<name> or /origins/<name>.
//
// The prefix ends up in a URL path that an authorization server fetches and
// compares by exact string, and in the registry JWKS URL, so anything that
// could normalize differently (dot segments, escapes, extra segments) is
// refused rather than cleaned.
func validateServerPrefix(serverPrefix string) error {
	var name string
	switch {
	case strings.HasPrefix(serverPrefix, server_structs.CachePrefix.String()):
		name = strings.TrimPrefix(serverPrefix, server_structs.CachePrefix.String())
	case strings.HasPrefix(serverPrefix, server_structs.OriginPrefix.String()):
		name = strings.TrimPrefix(serverPrefix, server_structs.OriginPrefix.String())
	default:
		return errors.Errorf("%q is not a cache or origin registry prefix", serverPrefix)
	}
	if !serverNamePattern.MatchString(name) || strings.Contains(name, "..") {
		return errors.Errorf("%q is not a valid server name", name)
	}
	return nil
}

// normalizeBaseURL returns an https base URL with no default port, query,
// fragment or trailing slash, so that the director and its servers derive
// byte-identical client_id URLs from the same configured endpoint.
func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.Wrapf(err, "invalid URL %q", raw)
	}
	if u.Host == "" {
		return "", errors.Errorf("URL %q has no host", raw)
	}
	if u.User != nil {
		return "", errors.Errorf("URL %q must not carry credentials", raw)
	}
	u.Scheme = "https"
	if u.Port() == "443" {
		u.Host = u.Hostname()
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.RawPath = ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String(), nil
}

// ClientIDMetadataDocumentURL is the client_id of the server whose registry
// prefix is serverPrefix, for a federation whose director is at
// directorEndpoint.
func ClientIDMetadataDocumentURL(directorEndpoint, serverPrefix string) (string, error) {
	if err := validateServerPrefix(serverPrefix); err != nil {
		return "", err
	}
	base, err := normalizeBaseURL(directorEndpoint)
	if err != nil {
		return "", errors.Wrap(err, "invalid director endpoint")
	}
	return base + ClientIDMetadataDocumentPath + serverPrefix, nil
}

// NewClientIDMetadataDocument builds the document the director serves for
// serverPrefix.  federationName is shown to the person approving the device
// flow, alongside the host of the client_id.
func NewClientIDMetadataDocument(directorEndpoint, registryEndpoint, serverPrefix, federationName string) (*ClientIDMetadataDocument, error) {
	clientID, err := ClientIDMetadataDocumentURL(directorEndpoint, serverPrefix)
	if err != nil {
		return nil, err
	}
	registry, err := normalizeBaseURL(registryEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "invalid registry endpoint")
	}
	kind := "origin"
	name := strings.TrimPrefix(serverPrefix, server_structs.OriginPrefix.String())
	if strings.HasPrefix(serverPrefix, server_structs.CachePrefix.String()) {
		kind = "cache"
		name = strings.TrimPrefix(serverPrefix, server_structs.CachePrefix.String())
	}
	clientName := fmt.Sprintf("Pelican %s %s", kind, name)
	if federationName != "" {
		clientName += " (" + federationName + ")"
	}
	directorBase, _ := normalizeBaseURL(directorEndpoint)
	return &ClientIDMetadataDocument{
		ClientID:                clientID,
		ClientName:              clientName,
		ClientURI:               directorBase,
		GrantTypes:              []string{grantTypeDeviceCode, grantTypeRefreshToken},
		TokenEndpointAuthMethod: authMethodPrivateKeyJWT,
		JWKSURI:                 registry + "/api/v1.0/registry" + serverPrefix + "/.well-known/issuer.jwks",
		SoftwareID:              pelicanSoftwareID,
		SoftwareVersion:         version.GetVersion(),
	}, nil
}

// fetchClientIDMetadataDocument retrieves the document at clientID and checks
// it is one this package can act as: it must name itself (an authorization
// server would reject it otherwise), allow the device and refresh grants, and
// use private_key_jwt.
//
// A successful fetch is how a server learns that its director publishes a
// document for it, so a director that predates this feature (or has it
// disabled) simply yields an error here and the caller falls back to dynamic
// client registration.
func fetchClientIDMetadataDocument(ctx context.Context, httpClient *http.Client, clientID string) (*ClientIDMetadataDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("the director does not publish a client metadata document at %s (HTTP %d)", clientID, resp.StatusCode)
	}
	doc := &ClientIDMetadataDocument{}
	if err := json.Unmarshal(body, doc); err != nil {
		return nil, errors.Wrapf(err, "invalid client metadata document at %s", clientID)
	}
	if doc.ClientID != clientID {
		return nil, errors.Errorf("client metadata document at %s names client_id %q", clientID, doc.ClientID)
	}
	if doc.TokenEndpointAuthMethod != authMethodPrivateKeyJWT {
		return nil, errors.Errorf("client metadata document at %s uses token_endpoint_auth_method %q, not %q", clientID, doc.TokenEndpointAuthMethod, authMethodPrivateKeyJWT)
	}
	if !slices.Contains(doc.GrantTypes, grantTypeDeviceCode) || !slices.Contains(doc.GrantTypes, grantTypeRefreshToken) {
		return nil, errors.Errorf("client metadata document at %s does not allow the device code and refresh token grants", clientID)
	}
	return doc, nil
}

// jwksServesKey fetches the JWK set at jwksURI and checks that it contains
// the public half of key, compared by RFC 7638 thumbprint.
func jwksServesKey(ctx context.Context, httpClient *http.Client, jwksURI string, key jwk.Key) error {
	if err := requireHTTPS("jwks_uri", jwksURI); err != nil {
		return err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return errors.Wrap(err, "failed to derive the public signing key")
	}
	want, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return errors.Wrap(err, "failed to compute the signing key's thumbprint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to fetch this server's keys from %s", jwksURI)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("the registry does not serve this server's keys at %s (HTTP %d); the server may not be registered or approved yet", jwksURI, resp.StatusCode)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return errors.Wrapf(err, "invalid key set at %s", jwksURI)
	}
	for i := 0; i < set.Len(); i++ {
		k, ok := set.Key(i)
		if !ok {
			continue
		}
		if got, err := k.Thumbprint(crypto.SHA256); err == nil && bytes.Equal(got, want) {
			return nil
		}
	}
	return errors.Errorf("the key set at %s does not contain this server's current signing key (kid %q); the registry may not have the new key yet", jwksURI, key.KeyID())
}
