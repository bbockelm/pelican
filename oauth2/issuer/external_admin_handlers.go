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

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// External issuers are defined in configuration, not the database, so the admin
// surface is read-only: list what is configured, and two diagnostics — probe
// (fetch discovery/JWKS now) and dry-run (evaluate a sample token through the
// real decision path without minting anything). Changing which issuers are
// trusted is a config edit, reviewed and applied like any other.

// handleAdminListExternalIssuers returns the trusted external issuers
// configured for this namespace.
func handleAdminListExternalIssuers(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		issuers := provider.ExternalIssuers()
		if issuers == nil {
			issuers = []ExternalIssuerDetail{}
		}
		ctx.JSON(http.StatusOK, issuers)
	}
}

// ExternalIssuerProbeResponse reports what discovery and a JWKS fetch found.
type ExternalIssuerProbeResponse struct {
	OK         bool     `json:"ok"`
	IssuerURL  string   `json:"issuer_url"`
	JWKSURL    string   `json:"jwks_url,omitempty"`
	KeyCount   int      `json:"key_count"`
	KeyIDs     []string `json:"key_ids,omitempty"`
	Algorithms []string `json:"algorithms,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// handleAdminProbeExternalIssuer fetches a configured issuer's discovery
// document and JWKS right now and reports what it found. The path segment is the
// issuer's configured Name.
func handleAdminProbeExternalIssuer(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		detail := ExternalIssuerByName(provider.ExternalIssuers(), ctx.Param("id"))
		if detail == nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "External issuer not found"})
			return
		}

		// A probe is an explicit "go look now", so it must not be answered from
		// a stale cache entry — including a cached failure from before the
		// operator fixed whatever was wrong.
		InvalidateExternalIssuerKeys(detail.IssuerURL)

		resp := ExternalIssuerProbeResponse{IssuerURL: detail.IssuerURL, JWKSURL: detail.JWKSURL}
		keySet, err := ExternalIssuerKeySet(ctx.Request.Context(), detail)
		if err != nil {
			resp.Error = err.Error()
			ctx.JSON(http.StatusOK, resp)
			return
		}
		resp.OK = true
		resp.KeyCount = keySet.Len()
		algSeen := map[string]bool{}
		for i := 0; i < keySet.Len(); i++ {
			key, ok := keySet.Key(i)
			if !ok {
				continue
			}
			if kid := key.KeyID(); kid != "" {
				resp.KeyIDs = append(resp.KeyIDs, kid)
			}
			if alg := key.Algorithm(); alg != nil && alg.String() != "" && !algSeen[alg.String()] {
				algSeen[alg.String()] = true
				resp.Algorithms = append(resp.Algorithms, alg.String())
			}
		}
		ctx.JSON(http.StatusOK, resp)
	}
}

// ExternalIssuerDryRunRequest carries a sample subject token to evaluate.
type ExternalIssuerDryRunRequest struct {
	SubjectToken string   `json:"subject_token"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes"`
}

// ExternalIssuerDryRunResponse reports what an exchange of the sample token
// would produce.
type ExternalIssuerDryRunResponse struct {
	OK             bool     `json:"ok"`
	Error          string   `json:"error,omitempty"`
	ExternalIssuer string   `json:"external_issuer,omitempty"`
	ExternalSub    string   `json:"external_subject,omitempty"`
	Username       string   `json:"username,omitempty"`
	UserID         string   `json:"user_id,omitempty"`
	WouldEnroll    bool     `json:"would_enroll"`
	Groups         []string `json:"groups,omitempty"`
	MatchedGroups  []string `json:"matched_groups,omitempty"`
	GrantedScopes  []string `json:"granted_scopes,omitempty"`
	LifetimeSecs   int      `json:"lifetime_seconds,omitempty"`
}

// handleAdminDryRunExternalIssuer evaluates a sample subject token through the
// real exchange decision path and reports the outcome without minting anything.
// It bypasses the per-client blessing (it is an admin diagnostic testing the
// issuer configuration itself), but still applies a client's scope allow-list
// when one is named so the reported scopes match what that client would get.
func handleAdminDryRunExternalIssuer(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if ExternalIssuerByName(provider.ExternalIssuers(), ctx.Param("id")) == nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "External issuer not found"})
			return
		}
		var req ExternalIssuerDryRunRequest
		if err := ctx.ShouldBindJSON(&req); err != nil || req.SubjectToken == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "subject_token is required"})
			return
		}

		clientScopes := []string{"openid", "offline_access", "wlcg", "pelican.transfer",
			"storage.read:/", "storage.modify:/", "storage.create:/",
			"collection.read:/", "collection.create:/", "collection.modify:/", "collection.delete:/"}
		if req.ClientID != "" {
			cd, cErr := provider.Storage().GetClientDetail(ctx.Request.Context(), req.ClientID)
			if cErr != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Unknown client_id"})
				return
			}
			clientScopes = cd.Scopes
		}

		// enroll=false, allowExternalExchange=true: a side-effect-free preview
		// that tests the issuer configuration regardless of client blessing.
		result, err := resolveExternalExchange(ctx, provider, true, clientScopes,
			req.SubjectToken, req.Scopes, IssuerURLForNamespace(provider.Namespace), false)
		if err != nil {
			ctx.JSON(http.StatusOK, ExternalIssuerDryRunResponse{OK: false, Error: err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, ExternalIssuerDryRunResponse{
			OK:             true,
			ExternalIssuer: result.Issuer.IssuerURL,
			ExternalSub:    result.ExternalSub,
			Username:       result.User.Username,
			UserID:         result.User.ID,
			WouldEnroll:    result.WouldEnroll,
			Groups:         result.Groups,
			MatchedGroups:  result.MatchedGroups,
			GrantedScopes:  result.GrantedScopes,
			LifetimeSecs:   int(result.Lifetime.Seconds()),
		})
	}
}
