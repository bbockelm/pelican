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

package origin_serve

// Authorizing a token issued by an HTCondor placement daemon.
//
// Such a token says nothing this origin can act on. It is HMAC-signed with a
// pool key Pelican does not hold, so there is no signature to check, and it
// carries HTCondor authorizations ("condor:/WRITE") rather than storage
// scopes, so there is nothing in it to honor even once it is known to be
// genuine. What the placement daemon can tell Pelican is a single fact: which
// identity the token speaks for.
//
// Everything else is Pelican's own answer to "what may that identity do
// here?", and it is deliberately the same answer the embedded issuer would
// give if that user had logged in and asked for a token: the configured
// authorization templates plus the collection ACLs the user holds. The
// placement daemon is an authentication source, not an authorization source —
// it cannot widen what a Pelican user may reach, and an administrator revoking
// a user's access in Pelican revokes it for their placement-daemon token too.
//
// The link between the two worlds is one row an administrator adds by hand: an
// identity in Pelican's identity table whose issuer is
// Origin.Placementd.IdentityIssuer and whose subject is the identity the
// placement daemon reports. No row, no access — the origin never invents a
// user for an identity it has not been told about.

import (
	"context"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/placementd"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// placementdVerifier is the part of placementd.Verifier this package uses. An
// interface so that tests can exercise identity resolution and scope
// derivation — which is where the authorization decisions are — without a
// placement daemon to talk to.
type placementdVerifier interface {
	// Recognize reports whether a token could be one the placement daemon
	// issued, from the token alone and without contacting it.
	Recognize(tokenStr string) bool
	// Verify returns the identity the placement daemon authenticates the
	// token as.
	Verify(ctx context.Context, tokenStr string) (placementd.Identity, error)
}

// storageAuthorizations are the scopes that mean anything to the data plane.
// The authorization templates and collection rules also yield collection.*
// management scopes, which belong to the web API and would be meaningless (and
// misleading, in a log of what a request was allowed) as filesystem ACLs.
var storageAuthorizations = map[token_scopes.TokenScope]struct{}{
	token_scopes.Wlcg_Storage_Read:   {},
	token_scopes.Wlcg_Storage_Create: {},
	token_scopes.Wlcg_Storage_Modify: {},
	token_scopes.Wlcg_Storage_Stage:  {},
}

// initPlacementd builds the placement-daemon verifier from configuration, and
// does nothing when no placement daemon is configured.
func (ac *authConfig) initPlacementd(ctx context.Context, egrp *errgroup.Group) error {
	verifier, err := placementd.NewVerifier(ctx, egrp, placementd.Config{
		Address:       param.Origin_Placementd_Address.GetString(),
		TrustDomain:   param.Origin_Placementd_TrustDomain.GetString(),
		Timeout:       param.Origin_Placementd_VerificationTimeout.GetDuration(),
		RatePerSecond: param.Origin_Placementd_VerificationsPerSecond.GetInt(),
		Burst:         param.Origin_Placementd_VerificationBurst.GetInt(),
		SuccessTTL:    param.Origin_Placementd_IdentityCacheTimeout.GetDuration(),
		FailureTTL:    param.Origin_Placementd_RefusalCacheTimeout.GetDuration(),
	})
	if err != nil {
		return errors.Wrap(err, "failed to configure HTCondor placement-daemon token verification")
	}
	if verifier == nil {
		// No placement daemon configured: leave ac.placementd nil rather
		// than storing a typed nil, which would read as configured.
		return nil
	}

	issuer := param.Origin_Placementd_IdentityIssuer.GetString()
	if issuer == "" {
		// A pool's trust domain is the natural name for identities that
		// come out of it, and is what the tokens themselves carry, so it
		// is the default. IdentityIssuer exists for the deployment that
		// already records these identities under some other name.
		issuer = verifier.TrustDomain()
	}
	ac.placementd = verifier
	ac.placementdIssuer = issuer
	log.Infof("Accepting tokens from the HTCondor placement daemon at %s (trust domain %s); identities are matched against Pelican identities with issuer %s",
		verifier.Address(), verifier.TrustDomain(), issuer)
	return nil
}

// compileAuthzRules compiles the authorization templates that apply to these
// exports: each export's own, where it defines them, and the global
// Issuer.AuthorizationTemplates for the rest.
//
// This mirrors what configureEmbeddedIssuer does per namespace, so that a
// placement-daemon token and a token minted by the embedded issuer are
// authorized by the same rules for the same export.
func (ac *authConfig) compileAuthzRules(exports []server_utils.OriginExport) (*authzRuleSet, error) {
	global, err := oa4mp.EnsureAuthzRules()
	if err != nil {
		return nil, errors.Wrap(err, "failed to compile Issuer.AuthorizationTemplates")
	}
	set := &authzRuleSet{global: global}
	for _, export := range exports {
		if len(export.AuthorizationTemplates) == 0 {
			continue
		}
		rules, err := oa4mp.CompileAuthzTemplates(export.AuthorizationTemplates)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to compile the authorization templates of export %s", export.FederationPrefix)
		}
		if set.byPrefix == nil {
			set.byPrefix = make(map[string][]*oa4mp.CompiledAuthz)
		}
		set.byPrefix[export.FederationPrefix] = rules
	}
	return set, nil
}

// placementdTokenInfo resolves a placement-daemon token all the way to a cache
// entry: the daemon is asked whose token it is, that identity is looked up as a
// Pelican user, and the user's authorization templates and collection ACLs
// become this origin's ACLs.
//
// The returned duration is how long the entry may be trusted, which is never
// past the token's own expiry.
func (ac *authConfig) placementdTokenInfo(tokenStr string) (cachedTokenInfo, time.Duration, error) {
	identity, err := ac.placementd.Verify(ac.ctx, tokenStr)
	if err != nil {
		return cachedTokenInfo{}, 0, err
	}

	db := database.ServerDatabase
	if db == nil {
		return cachedTokenInfo{}, 0, errors.New("the origin has no database in which to look up placement-daemon identities")
	}

	user, err := database.GetUserByIdentity(db, identity.Subject, ac.placementdIssuer)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return cachedTokenInfo{}, 0, errors.Errorf("the placement daemon authenticated identity %q, which is not linked to any Pelican user under issuer %q; link it to a user to grant it access",
				identity.Subject, ac.placementdIssuer)
		}
		return cachedTokenInfo{}, 0, errors.Wrapf(err, "failed to look up the Pelican user linked to placement-daemon identity %q", identity.Subject)
	}
	if user.Status != database.UserStatusActive {
		return cachedTokenInfo{}, 0, errors.Errorf("the Pelican user %q linked to placement-daemon identity %q is %s", user.Username, identity.Subject, user.Status)
	}

	// Only memberships that may confer authority right now: the same view
	// the issuer and the collection API grant from.
	groups, err := database.GroupNamesForGranting(db, user.ID)
	if err != nil {
		// Granting on a partial group list is safe (it can only authorize
		// less); granting on a list we failed to read and silently calling
		// it empty is not something to do quietly.
		log.Warningf("Failed to read the group memberships of user %s while authorizing a placement-daemon token; authorizing without them: %v", user.Username, err)
		groups = nil
	}

	// The local identity the data plane acts as follows the Pelican user,
	// not the placement daemon's identity string: from here on this request
	// is that user, and a multi-user backend should impersonate them. An
	// operator who needs a different local account maps the Pelican
	// username in Origin.ScitokensNameMapFile.
	userInfo := ac.userMapper.MapIdentityToUser(user.Username, groups)
	if userInfo == nil {
		return cachedTokenInfo{}, 0, errors.Errorf("no mapfile rule matched Pelican user %q and no default user is configured", user.Username)
	}

	info := cachedTokenInfo{
		Scopes:   ac.placementdAcls(db, user, groups),
		UserInfo: userInfo,
		Issuer:   ac.placementdIssuer,
	}

	ttl := ttlcache.DefaultTTL
	if !identity.Expiration.IsZero() {
		until := time.Until(identity.Expiration)
		if until <= 0 {
			return cachedTokenInfo{}, 0, errors.New("the placement-daemon token has expired")
		}
		if until < tokenAuthzTTL {
			ttl = until
		}
	}

	log.WithFields(log.Fields{
		"identity": identity.Subject,
		"user":     user.Username,
		"groups":   groups,
		"scopes":   len(info.Scopes),
	}).Debug("Authorized a placement-daemon token")

	return info, ttl, nil
}

// placementdAcls computes the ACLs a Pelican user holds across this origin's
// exports, from the authorization templates and the collection ACLs.
//
// Both inputs produce namespace-relative scopes, exactly as the scopes in a
// presented token are, so the result goes through appendScopesForExport like
// any other — the export's capabilities still have the last word.
func (ac *authConfig) placementdAcls(db *gorm.DB, user *database.User, groups []string) acls {
	out := make(acls, 0)
	exports := ac.exports.Load()
	if exports == nil {
		return out
	}
	rules := ac.authzRules.Load()

	for _, export := range *exports {
		if export.Capabilities.PublicReads {
			out = append(out, token_scopes.ResourceScope{
				Authorization: token_scopes.Wlcg_Storage_Read,
				Resource:      export.FederationPrefix,
			})
		}

		var exportRules []*oa4mp.CompiledAuthz
		if rules != nil {
			exportRules = rules.global
			if own, ok := rules.byPrefix[export.FederationPrefix]; ok {
				exportRules = own
			}
		}

		scopes, _ := oa4mp.CalculateAllowedScopesWithRules(exportRules, user.Username, user.ID, groups)

		// Collection ACLs are scoped to this export's namespace, so a
		// collection living under another export contributes nothing here.
		collectionScopes, _, err := oa4mp.GetUserCollectionScopes(db, user.Username, user.ID, groups, export.FederationPrefix)
		if err != nil {
			log.Warningf("Failed to read the collection ACLs of user %s for export %s; authorizing without them: %v", user.Username, export.FederationPrefix, err)
		} else {
			scopes = append(scopes, collectionScopes...)
		}

		out = appendScopesForExport(out, export, storageScopes(scopes))
	}
	return out
}

// storageScopes parses scope strings and keeps only the ones the data plane
// can act on.
func storageScopes(scopes []string) []token_scopes.ResourceScope {
	parsed := token_scopes.ParseResourceScopes(scopes)
	kept := make([]token_scopes.ResourceScope, 0, len(parsed))
	for _, scope := range parsed {
		if _, ok := storageAuthorizations[scope.Authorization]; ok {
			kept = append(kept, scope)
		}
	}
	return kept
}
