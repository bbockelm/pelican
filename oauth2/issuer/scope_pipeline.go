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
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oa4mp"
)

// userAuthorization is the issuer's answer to "what may this identity be
// granted?", computed once from the authorization templates, the user's
// collection ACLs, and their group memberships.
//
// Every grant path — the authorization-code flow, the device-code flow, and
// token exchange — runs through this type. That is the point: the exchange
// path must not be able to compute authorizations differently from the
// interactive flows, because a divergence between them is a privilege bug that
// only shows up on one route.
type userAuthorization struct {
	user   string
	userID string
	groups []string

	// allowedScopes is everything this identity could receive, before the
	// request and the client's allow-list narrow it.
	allowedScopes []string
	// matchedGroups is the subset of groups that actually drove an
	// authorization; it becomes the token's wlcg.groups claim.
	matchedGroups []string

	db *gorm.DB
}

// authorizeUser computes the full set of scopes an identity may be granted by
// this provider.
func (p *OIDCProvider) authorizeUser(user, userID string, groups []string) *userAuthorization {
	a := &userAuthorization{user: user, userID: userID, groups: groups}

	if len(p.AuthzRules) > 0 {
		a.allowedScopes, a.matchedGroups = oa4mp.CalculateAllowedScopesWithRules(p.AuthzRules, user, userID, groups)
	} else {
		a.allowedScopes, a.matchedGroups = oa4mp.CalculateAllowedScopes(user, userID, groups)
	}

	a.db = database.ServerDatabase
	if a.db == nil {
		a.db = p.storage.db
	}

	collectionScopes, collectionGroups, err := oa4mp.GetUserCollectionScopes(a.db, user, userID, groups, p.Namespace)
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to get collection scopes")
	} else {
		a.allowedScopes = append(a.allowedScopes, collectionScopes...)
		a.matchedGroups = oa4mp.MergeGroups(a.matchedGroups, collectionGroups)
	}
	return a
}

// grantable narrows a set of requested scopes to those that may actually be
// issued, applying — in order — the user's own authorization and then the
// client's configured allow-list.
//
// A request broader than what the user holds is not an error: it is narrowed to
// every permitted scope beneath it, so a client asking for `storage.read:/` on
// behalf of a user authorized only under `/home/alice` receives the latter.
func (a *userAuthorization) grantable(requested []string, clientScopes []string) []string {
	granted := make([]string, 0, len(requested))
	for _, scope := range requested {
		scope = cleanScopePath(scope)
		var candidates []string
		switch {
		case scope == "pelican.transfer":
			// Authorization-gated, not a free standard scope: granted only to
			// users permitted to use the transfer API.
			if transferAccessAllowed(a.db, a.userID, a.groups) {
				candidates = []string{scope}
			}
		case isStandardScope(scope) || scopeAllowed(scope, a.allowedScopes):
			candidates = []string{scope}
		default:
			candidates = collectNarrowerScopes(scope, a.allowedScopes)
		}
		for _, s := range candidates {
			if scopeAllowed(s, clientScopes) {
				granted = append(granted, s)
			}
		}
	}
	return granted
}
