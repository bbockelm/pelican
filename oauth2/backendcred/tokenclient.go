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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

const (
	grantTypeDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	grantTypeRefreshToken = "refresh_token"
	clientAssertionType   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// Token endpoint error codes (RFC 6749 section 5.2, RFC 8628 section 3.5).
	errCodeAuthorizationPending = "authorization_pending"
	errCodeSlowDown             = "slow_down"
	errCodeInvalidGrant         = "invalid_grant"
	errCodeInvalidClient        = "invalid_client"
	errCodeUnauthorizedClient   = "unauthorized_client"

	// The longest response body read from an authorization server.
	maxResponseBytes = 1 << 20
)

// clientAuthenticator adds client authentication to a request bound for the
// token or device-authorization endpoint.
//
// It is called once per request, so an authenticator that mints per-request
// material -- the private_key_jwt assertion, whose jti an authorization server
// may refuse to see twice -- produces a fresh value for every poll and every
// refresh.
type clientAuthenticator interface {
	authenticate(form url.Values, header http.Header) error
}

// publicClient identifies itself without authenticating: the client_id travels
// in the request body (token_endpoint_auth_method "none").
type publicClient struct {
	clientID string
}

func (c publicClient) authenticate(form url.Values, _ http.Header) error {
	form.Set("client_id", c.clientID)
	return nil
}

// secretBasicClient authenticates with HTTP Basic, form-encoding the
// credentials first as RFC 6749 section 2.3.1 requires.
type secretBasicClient struct {
	clientID     string
	clientSecret string
}

func (c secretBasicClient) authenticate(_ url.Values, header http.Header) error {
	req := http.Request{Header: header}
	req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
	return nil
}

// privateKeyJWTClient authenticates with a JWT signed by the server's own
// issuer key (RFC 7523 section 2.2, token_endpoint_auth_method
// "private_key_jwt").  The authorization server verifies the signature with
// the keys at the client's jwks_uri, which for a client described by a
// Pelican director's metadata document is the server's registration in the
// federation registry.
type privateKeyJWTClient struct {
	clientID string
	// audience is the authorization server's issuer identifier.
	audience string
	key      func() (jwk.Key, error)
	now      func() time.Time
}

func (c privateKeyJWTClient) authenticate(form url.Values, _ http.Header) error {
	assertion, err := c.assertion()
	if err != nil {
		return err
	}
	form.Set("client_id", c.clientID)
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", assertion)
	return nil
}

func (c privateKeyJWTClient) assertion() (string, error) {
	if c.key == nil {
		return "", errors.New("no key is configured to sign client assertions")
	}
	key, err := c.key()
	if err != nil {
		return "", errors.Wrap(err, "failed to load the key that signs client assertions")
	}
	alg, err := config.SigningAlgorithmForJWK(key)
	if err != nil {
		return "", errors.Wrap(err, "failed to determine the client assertion signing algorithm")
	}
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	// The audience is the issuer identifier rather than the token endpoint:
	// draft-ietf-oauth-rfc7523bis makes that the only acceptable value, closing
	// the confusion attacks that a token-endpoint audience allows.
	tok, err := jwt.NewBuilder().
		Issuer(c.clientID).
		Subject(c.clientID).
		Audience([]string{c.audience}).
		JwtID(uuid.NewString()).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		Build()
	if err != nil {
		return "", errors.Wrap(err, "failed to build the client assertion")
	}
	// A single audience is serialized as a bare string, the form every
	// RFC 7523 implementation accepts.
	tok.Options().Enable(jwt.FlattenAudience)
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	if err != nil {
		return "", errors.Wrap(err, "failed to sign the client assertion")
	}
	return string(signed), nil
}

// TokenError is an error response from an authorization server's token or
// device-authorization endpoint.
type TokenError struct {
	StatusCode  int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *TokenError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("authorization server returned %s (HTTP %d): %s", e.Code, e.StatusCode, e.Description)
	}
	if e.Code != "" {
		return fmt.Sprintf("authorization server returned %s (HTTP %d)", e.Code, e.StatusCode)
	}
	return fmt.Sprintf("authorization server returned HTTP %d", e.StatusCode)
}

// tokenErrorCode returns the OAuth error code carried by err, or "".
func tokenErrorCode(err error) string {
	var te *TokenError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	// Some servers (Azure AD among them) spell it verification_url.
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int64  `json:"interval"`
}

// tokenClient speaks the token and device-authorization endpoints of one
// authorization server on behalf of one client.
type tokenClient struct {
	httpClient    *http.Client
	tokenURL      string
	deviceAuthURL string
	auth          clientAuthenticator
}

// post sends form to endpoint with client authentication and decodes a JSON
// success body into out.  An OAuth error response comes back as *TokenError.
func (c *tokenClient) post(ctx context.Context, endpoint string, form url.Values, out any) error {
	header := http.Header{}
	if err := c.auth.authenticate(form, header); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return errors.Wrapf(err, "failed to read the response from %s", endpoint)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		te := &TokenError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(body, te)
		return te
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.Wrapf(err, "invalid response from %s", endpoint)
	}
	return nil
}

func scopeParams(form url.Values, scopes []string, audience string) {
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	if audience != "" {
		form.Set("audience", audience)
	}
}

// authorizeDevice starts a device authorization grant (RFC 8628 section 3.1).
func (c *tokenClient) authorizeDevice(ctx context.Context, scopes []string, audience string) (*deviceAuthorization, error) {
	if c.deviceAuthURL == "" {
		return nil, errors.New("the authorization server does not advertise a device_authorization_endpoint")
	}
	form := url.Values{}
	scopeParams(form, scopes, audience)
	da := &deviceAuthorization{}
	if err := c.post(ctx, c.deviceAuthURL, form, da); err != nil {
		return nil, errors.Wrap(err, "device authorization request failed")
	}
	if da.VerificationURI == "" {
		da.VerificationURI = da.VerificationURL
	}
	if da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		return nil, errors.New("device authorization response is missing device_code, user_code or verification_uri")
	}
	return da, nil
}

// pollDeviceToken makes one device access token request (RFC 8628 section
// 3.4).  Pending and slow-down answers come back as *TokenError so the caller
// can pace its next attempt.
func (c *tokenClient) pollDeviceToken(ctx context.Context, deviceCode string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":  {grantTypeDeviceCode},
		"device_code": {deviceCode},
	}
	tr := &tokenResponse{}
	if err := c.post(ctx, c.tokenURL, form, tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token response is missing access_token")
	}
	return tr, nil
}

// refresh redeems a refresh token (RFC 6749 section 6).
func (c *tokenClient) refresh(ctx context.Context, refreshToken string, scopes []string, audience string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":    {grantTypeRefreshToken},
		"refresh_token": {refreshToken},
	}
	scopeParams(form, scopes, audience)
	tr := &tokenResponse{}
	if err := c.post(ctx, c.tokenURL, form, tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token response is missing access_token")
	}
	return tr, nil
}
