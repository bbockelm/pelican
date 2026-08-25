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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
)

// externalExchangeResult is what a successful external exchange resolves to,
// before any token is minted. Separating the decision from the minting is what
// lets the admin dry-run endpoint answer "what would happen?" using exactly the
// code path a real exchange takes.
type externalExchangeResult struct {
	Issuer      *ExternalIssuerDetail
	ExternalSub string
	User        *database.User
	// WouldEnroll is true when no account is linked yet and one would be (or
	// was, on the live path) created for this identity.
	WouldEnroll   bool
	Groups        []string
	MatchedGroups []string
	GrantedScopes []string
	// Lifetime is the access-token lifespan after every cap is applied.
	Lifetime time.Duration
}

// resolveExternalExchange runs every check an external token exchange requires
// and reports what the resulting token would contain. It mints nothing.
func resolveExternalExchange(ctx *gin.Context, provider *OIDCProvider, allowExternalExchange bool,
	clientScopes []string, subjectToken string, requestedScopes []string, issuerURL string, enroll bool) (*externalExchangeResult, error) {

	rCtx := ctx.Request.Context()

	// The `iss` read here is unverified — it only selects which trust anchor to
	// evaluate against. VerifyExternalToken re-checks it against the verified
	// claims, so a forged `iss` can at worst pick a trust anchor whose keys
	// will not validate the token.
	rawIssuer, ok := PeekTokenIssuer(subjectToken)
	if !ok {
		return nil, errors.New("subject token is not a JWT issued by a trusted external issuer")
	}

	detail := ExternalIssuerByURL(provider.ExternalIssuers(), rawIssuer)
	if detail == nil {
		// Deliberately does not distinguish "not configured" from "disabled": a
		// caller should not be able to enumerate which issuers this server
		// trusts, and an unknown issuer costs no outbound network request.
		return nil, errors.New("the subject token's issuer is not trusted by this server")
	}

	// A client must be explicitly blessed for external exchange (all-or-none of
	// the namespace's configured issuers). Empty/false is the default, so every
	// client that merely holds the token-exchange grant keeps accepting only
	// tokens this server issued.
	if !allowExternalExchange {
		return nil, errors.New("this client is not authorized to exchange tokens from external issuers")
	}

	parsed, err := VerifyExternalToken(rCtx, detail, subjectToken)
	if err != nil {
		return nil, err
	}

	serverDB := database.ServerDatabase
	if serverDB == nil {
		serverDB = provider.storage.db
	}

	user, wouldEnroll, err := resolveOrPreviewExternalUser(serverDB, detail, parsed, enroll)
	if err != nil {
		return nil, err
	}
	// In mapped mode the issuer's inline external->local table is the
	// allow-list; the other modes do not consult it.
	var groupMapping map[string]string
	if detail.GroupMode == GroupModeMapped {
		groupMapping = detail.GroupMappings
	}

	groups, err := ResolveExternalGroups(serverDB, detail, parsed, user, groupMapping)
	if err != nil {
		return nil, err
	}

	// The exchanged token's authorizations are computed from the *local* user's
	// rules, never inherited from the foreign token. The foreign token's own
	// scopes are a precondition for accepting it at all (required_scopes), not
	// an input here: Keycloak's scope vocabulary is not Pelican's, and a scope
	// string minted elsewhere carries no authority over this server's data.
	authz := provider.authorizeUser(user.Username, user.ID, groups)

	// With no explicit request, grant everything the user is authorized for.
	// Protocol scopes (openid, offline_access) are not included implicitly —
	// a caller that wants them asks for them.
	effectiveRequest := requestedScopes
	if len(effectiveRequest) == 0 {
		effectiveRequest = authz.allowedScopes
	}
	granted := authz.grantable(effectiveRequest, clientScopes)

	lifetime := provider.config.AccessTokenLifespan
	if detail.MaxTokenLifetimeSeconds > 0 {
		if capped := time.Duration(detail.MaxTokenLifetimeSeconds) * time.Second; capped < lifetime {
			lifetime = capped
		}
	}
	// Never outlive the assertion that justified it. Once the Keycloak token
	// has expired there is nothing left vouching for this user, so a Pelican
	// token minted from it should not still be good.
	if exp := parsed.Expiration(); !exp.IsZero() {
		if remaining := time.Until(exp); remaining < lifetime {
			lifetime = remaining
		}
	}
	if lifetime <= 0 {
		return nil, errors.New("the subject token expires too soon to exchange")
	}

	sub, _ := ExternalSubject(parsed, detail)
	return &externalExchangeResult{
		Issuer:        detail,
		ExternalSub:   sub,
		User:          user,
		WouldEnroll:   wouldEnroll,
		Groups:        groups,
		MatchedGroups: authz.matchedGroups,
		GrantedScopes: granted,
		Lifetime:      lifetime,
	}, nil
}

// handleExternalTokenExchange completes an RFC 8693 exchange whose subject
// token was issued by a trusted external issuer.
//
// It is reached from handleTokenExchange once the subject token's `iss` is
// found not to be this server's own; the client has already been authenticated
// and checked for the token-exchange grant by then.
func handleExternalTokenExchange(ctx *gin.Context, provider *OIDCProvider, client fosite.Client,
	dc *fosite.DefaultClient, allowExternalExchange bool, subjectToken string, requestedScopes []string) {

	rCtx := ctx.Request.Context()
	issuerURL := IssuerURLForNamespace(provider.Namespace)

	if param.Issuer_DisableExternalTokenExchange.GetBool() {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Exchanging tokens from external issuers is disabled on this server",
		})
		return
	}

	result, err := resolveExternalExchange(ctx, provider, allowExternalExchange, dc.Scopes,
		subjectToken, requestedScopes, issuerURL, true /* enroll */)
	if err != nil {
		// Every failure is reported as invalid_grant with the underlying reason,
		// which is safe here: the caller is an authenticated client, and telling
		// it *why* its exchange failed is the difference between a debuggable
		// integration and a black box.
		log.WithError(err).Debug("Embedded issuer: external token exchange refused")
		// invalid_grant for every refusal. RFC 8693 inherits RFC 6749's
		// token-endpoint error set, in which access_denied is NOT a member
		// (it is an authorization-endpoint code); a "no linked account" or
		// "inactive account" outcome is a grant that cannot be honored, which
		// invalid_grant is exactly for.
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	session := DefaultOIDCSession(result.User.Username, issuerURL, result.MatchedGroups, result.GrantedScopes)
	// RFC 8693 §4.1: record the acting party, so the provenance of an exchanged
	// token survives into logs and introspection. Purely informational to WLCG
	// consumers, invaluable when reconstructing who did what.
	if session.JWTClaims != nil && session.JWTClaims.Extra != nil {
		session.JWTClaims.Extra["act"] = map[string]interface{}{
			"sub": result.ExternalSub,
			"iss": result.Issuer.IssuerURL,
		}
	}
	session.SetExpiresAt(fosite.AccessToken, time.Now().Add(result.Lifetime))

	ar := fosite.NewAccessRequest(session)
	ar.Client = client
	ar.GrantedScope = result.GrantedScopes
	ar.RequestedScope = requestedScopes
	ar.Session = session
	// Only the WLCG wildcard. A specific audience is not honored on this path:
	// the local exchange validates a requested audience against the subject
	// token's own granted audiences, and a foreign token carries no such
	// statement about Pelican services.
	ar.GrantAudience(WLCGAudienceAny)

	accessToken, accessSignature, err := provider.strategy.CoreStrategy.GenerateAccessToken(rCtx, ar)
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to generate external token-exchange access token")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to generate access token"})
		return
	}
	if err := provider.storage.CreateAccessTokenSession(rCtx, accessSignature, ar); err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to store external token-exchange access token")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to store access token"})
		return
	}

	_ = provider.storage.TouchClientLastUsed(rCtx, dc.ID)

	// One audit line per exchange, carrying every input to the decision.
	log.WithFields(log.Fields{
		"client":          dc.ID,
		"external_issuer": result.Issuer.IssuerURL,
		"external_sub":    result.ExternalSub,
		"user":            result.User.Username,
		"user_id":         result.User.ID,
		"groups":          result.MatchedGroups,
		"scopes":          result.GrantedScopes,
		"lifetime":        result.Lifetime.String(),
	}).Info("Embedded issuer: external token exchange granted")

	response := gin.H{
		"access_token":      accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        int(result.Lifetime.Seconds()),
		"scope":             strings.Join(result.GrantedScopes, " "),
	}

	// A refresh token here outlives the foreign session that justified it —
	// past the user's group changes, and past their departure from the
	// project. That can be legitimate, but it is a deliberate per-issuer
	// choice rather than a side effect of requesting a scope.
	if result.Issuer.AllowRefresh {
		hasRefreshGrant := false
		for _, gt := range dc.GrantTypes {
			if gt == "refresh_token" {
				hasRefreshGrant = true
				break
			}
		}
		if hasRefreshGrant && containsScope(result.GrantedScopes, "offline_access") {
			ar.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().Add(provider.config.RefreshTokenLifespan))
			rt, rtSig, rtErr := provider.strategy.CoreStrategy.GenerateRefreshToken(rCtx, ar)
			if rtErr != nil {
				log.WithError(rtErr).Warn("Embedded issuer: failed to generate external token-exchange refresh token")
			} else if rtErr = provider.storage.CreateRefreshTokenSession(rCtx, rtSig, accessSignature, ar); rtErr != nil {
				log.WithError(rtErr).Warn("Embedded issuer: failed to store external token-exchange refresh token")
			} else {
				response["refresh_token"] = rt
			}
		}
	}

	ctx.Header("Content-Type", "application/json;charset=UTF-8")
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.JSON(http.StatusOK, response)
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// subjectTokenIsExternal reports whether a subject token claims an issuer other
// than this provider's own, i.e. whether the external path should handle it.
func subjectTokenIsExternal(subjectToken, localIssuer string) bool {
	iss, ok := PeekTokenIssuer(subjectToken)
	if !ok {
		// Not a JWT (or no `iss`): an opaque token can only be one this server
		// issued, so leave it to the local path.
		return false
	}
	return NormalizeIssuerURL(iss) != NormalizeIssuerURL(localIssuer)
}
