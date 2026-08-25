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

package issuer

import "time"

// OIDCClientRecord maps to the oidc_clients table.
// The composite primary key (ID, Namespace) ensures that client IDs are unique
// per namespace rather than globally, preventing cross-namespace collisions.
type OIDCClientRecord struct {
	ID                      string `gorm:"primaryKey"`
	Namespace               string `gorm:"primaryKey"`
	ClientSecret            string
	RedirectURIs            string
	GrantTypes              string
	ResponseTypes           string
	Scopes                  string
	Public                  bool
	DynamicallyRegistered   bool
	BoundUser               string
	LastUsedAt              *time.Time
	RegistrationIP          string
	RegistrationAccessToken string
	ClientName              string
	// AllowExternalExchange blesses this client to exchange tokens from ANY of
	// the namespace's configured external issuers (all-or-none). False (the
	// default) means it may only exchange tokens this server issued.
	AllowExternalExchange bool
	CreatedAt             time.Time
}

func (OIDCClientRecord) TableName() string { return "oidc_clients" }

// ExternalIssuerRecord maps to the oidc_external_issuers table: a foreign
// OAuth2/OIDC issuer whose access tokens this server is willing to accept as
// the subject_token of an RFC 8693 token exchange.
//
// The composite primary key (ID, Namespace) mirrors OIDCClientRecord so that a
// multi-export origin can trust different identity providers for different
// federation prefixes.
//
// JSON-encoded TEXT columns follow the convention already used for the client
// record's RedirectURIs/GrantTypes/Scopes; use ExternalIssuerDetail (see
// external_issuer.go) for the decoded, API-facing form.
type ExternalIssuerRecord struct {
	ID        string `gorm:"primaryKey"`
	Namespace string `gorm:"primaryKey"`
	Name      string
	IssuerURL string
	JWKSURL   string
	Enabled   bool

	// Preconditions on the subject token.
	RequiredAudiences string // JSON []string
	AllowAnyAudience  bool
	RequiredScopes    string // JSON []string
	RequiredClaims    string // JSON map[string]string
	AllowedAlgorithms string // JSON []string

	// Identity mapping.
	SubjectClaim   string
	UsernameClaims string // JSON []string
	AutoEnroll     bool

	// Group mapping.
	GroupClaim         string
	GroupMode          string
	GroupPrefix        string
	AllowFlatGroups    bool
	GroupAllowPatterns string // JSON []string
	IncludeLocalGroups bool

	// Policy for the token minted in return.
	AllowRefresh            bool
	MaxTokenLifetimeSeconds int64

	CreatedBy           string
	CreatorAuthMethod   string
	CreatorAuthMethodID string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (ExternalIssuerRecord) TableName() string { return "oidc_external_issuers" }

// ExternalGroupMapRecord maps to the oidc_external_group_maps table: one
// external-group -> local-group correspondence for an issuer running in
// "mapped" group mode.
//
// Unlike the prefixed names "claim" mode produces, a mapped local group is an
// ordinary local group name and carries whatever that name carries. That is the
// point of the mode, and the reason it is opt-in per issuer.
type ExternalGroupMapRecord struct {
	ID               string `gorm:"primaryKey"`
	Namespace        string
	ExternalIssuerID string
	ExternalGroup    string
	LocalGroup       string
	CreatedBy        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (ExternalGroupMapRecord) TableName() string { return "oidc_external_group_maps" }

// OIDCTokenSession maps to the oidc_access_tokens, oidc_authorization_codes,
// oidc_pkce_requests, and oidc_openid_sessions tables. It is also used to
// create rows in oidc_refresh_tokens (which adds a first_used_at column
// not present in the other four tables).
type OIDCTokenSession struct {
	Signature       string `gorm:"primaryKey"`
	RequestID       string
	RequestedAt     time.Time
	ClientID        string
	Scopes          string
	GrantedScopes   string
	GrantedAudience string
	FormData        string
	SessionData     string
	Subject         string
	Active          bool
	ExpiresAt       *time.Time
	Namespace       string
	CreatedAt       time.Time
}

// OIDCRefreshToken extends OIDCTokenSession with the first_used_at column
// specific to the oidc_refresh_tokens table.
type OIDCRefreshToken struct {
	OIDCTokenSession
	FirstUsedAt *time.Time
}

func (OIDCRefreshToken) TableName() string { return "oidc_refresh_tokens" }

// OIDCDeviceCode maps to the oidc_device_codes table.
type OIDCDeviceCode struct {
	DeviceCode    string `gorm:"primaryKey"`
	UserCode      string
	RequestID     string
	RequestedAt   time.Time
	ClientID      string
	Scopes        string
	GrantedScopes string
	FormData      string
	SessionData   string
	Subject       string
	Status        string
	ExpiresAt     time.Time
	LastPolledAt  *time.Time
	Namespace     string
	CreatedAt     time.Time
}

func (OIDCDeviceCode) TableName() string { return "oidc_device_codes" }

// OIDCJWTAssertion maps to the oidc_jwt_assertions table.
type OIDCJWTAssertion struct {
	JTI       string `gorm:"column:jti;primaryKey"`
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (OIDCJWTAssertion) TableName() string { return "oidc_jwt_assertions" }
