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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
)

const (
	// maxExternalGroups bounds how many group names one foreign token can
	// contribute. A token asserting thousands of groups is either broken or
	// hostile; either way it should not be able to make scope computation
	// quadratic or produce an unusable token.
	maxExternalGroups = 256
	// maxExternalGroupLen bounds the length of a single group name.
	maxExternalGroupLen = 128
)

// ErrNoLinkedAccount is returned when a verified external identity has no
// Pelican account and the issuer is not configured to enroll one.
var ErrNoLinkedAccount = errors.New("no Pelican account is linked to this identity")

// ErrAccountNotActive is returned when the mapped account exists but has been
// deactivated (or soft-deleted) since it was linked.
var ErrAccountNotActive = errors.New("the Pelican account linked to this identity is not active")

// claimAsString reads a claim that should be a string, tolerating the numeric
// subjects some providers emit (GitHub-style integer IDs).
//
// This mirrors the coercion the web-login path already performs; a subject that
// changes representation between providers should not change the identity it
// maps to.
func claimAsString(parsed jwt.Token, name string) (string, bool) {
	if name == "sub" {
		if s := parsed.Subject(); s != "" {
			return s, true
		}
	}
	raw, ok := parsed.Get(name)
	if !ok {
		return "", false
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return "", false
		}
		return v, true
	case float64:
		// Reject anything that is not an exact integer: silently rounding a
		// subject would map two different users onto one account.
		if v != float64(int64(v)) {
			return "", false
		}
		return fmt.Sprintf("%d", int64(v)), true
	case int64:
		return fmt.Sprintf("%d", v), true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}

// ExternalSubject extracts the identity key from a verified token, per the
// issuer's configured subject claim.
func ExternalSubject(parsed jwt.Token, detail *ExternalIssuerDetail) (string, error) {
	sub, ok := claimAsString(parsed, detail.SubjectClaim)
	if !ok {
		return "", errors.Errorf("subject token has no usable %q claim", detail.SubjectClaim)
	}
	return sub, nil
}

// ResolveExternalUser maps a verified external identity onto a local user,
// enrolling one if the issuer is configured to do so.
//
// Enrollment deliberately never tries to *match* an existing account by email
// or any other claim: whoever controls that claim at the foreign IdP would then
// choose which local account they land on. An identity is either already
// linked — in the users table or in user_identities — or it is new.
func ResolveExternalUser(db *gorm.DB, detail *ExternalIssuerDetail, parsed jwt.Token) (*database.User, error) {
	user, _, err := resolveOrPreviewExternalUser(db, detail, parsed, true)
	return user, err
}

// resolveOrPreviewExternalUser maps a verified identity to a local user,
// reporting whether enrollment would happen.
//
// When enroll is false NOTHING is written: a not-yet-linked identity yields an
// in-memory, unsaved *database.User carrying only the username enrollment would
// choose, and wouldEnroll is true. This is what lets the admin "dry-run"
// endpoint answer "who would this become?" using the real decision path without
// the side effect of actually creating the account — a dry run that enrolled a
// user would be a surprising, and one-shot, mutation.
func resolveOrPreviewExternalUser(db *gorm.DB, detail *ExternalIssuerDetail, parsed jwt.Token, enroll bool) (*database.User, bool, error) {
	sub, err := ExternalSubject(parsed, detail)
	if err != nil {
		return nil, false, err
	}

	user, err := database.GetUserByIdentity(db, sub, detail.IssuerURL)
	if err == nil {
		if user.Status != database.UserStatusActive {
			return nil, false, ErrAccountNotActive
		}
		return user, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}

	if !detail.AutoEnroll {
		return nil, false, ErrNoLinkedAccount
	}

	candidates := make([]string, 0, len(detail.UsernameClaims))
	for _, claim := range detail.UsernameClaims {
		if v, ok := claimAsString(parsed, claim); ok {
			candidates = append(candidates, v)
		}
	}
	if len(candidates) == 0 {
		// Fall back to the subject so enrollment still produces an account;
		// LookupOrBootstrapUser sanitizes and disambiguates it.
		candidates = append(candidates, sub)
	}

	displayName := ""
	for _, claim := range []string{"name", "display_name", "preferred_username", "email"} {
		if v, ok := claimAsString(parsed, claim); ok {
			displayName = v
			break
		}
	}

	if !enroll {
		// Preview only: report the username enrollment would pick, without
		// creating anything. The displayName pick and disambiguation are not
		// reproduced here — an unsaved preview does not need them, and the
		// live path (enroll=true) is the authority on the final username.
		previewName := sub
		if len(candidates) > 0 {
			previewName = candidates[0]
		}
		return &database.User{Username: previewName}, true, nil
	}

	creator := database.Creator{
		UserID:       database.CreatorExternalExchange,
		AuthMethod:   database.AuthMethodBearerJWT,
		AuthMethodID: detail.Name,
	}
	user, err = database.LookupOrBootstrapUserWithCreator(db, sub, detail.IssuerURL, displayName, candidates, creator)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to enroll a Pelican account for this identity")
	}
	log.Infof("Embedded issuer: enrolled user %s (%s) from external issuer %s via token exchange",
		user.Username, user.ID, detail.Name)
	return user, true, nil
}

// externalGroupsFromClaim reads the group names a foreign token asserts and
// turns them into names Pelican is willing to reason about.
//
// mapping is non-nil only in GroupModeMapped, where it is the complete
// allow-list: a name with no entry is dropped, and a name with one is replaced
// by the local group the operator chose. In GroupModeClaim the names survive
// filtering and are namespaced behind the issuer's prefix instead.
func externalGroupsFromClaim(detail *ExternalIssuerDetail, parsed jwt.Token, mapping map[string]string) []string {
	if detail.GroupClaim == "" {
		return nil
	}
	if detail.GroupMode != GroupModeClaim && detail.GroupMode != GroupModeMapped {
		return nil
	}
	raw, ok := parsed.Get(detail.GroupClaim)
	if !ok {
		return nil
	}

	var names []string
	switch v := raw.(type) {
	case string:
		// Some providers emit a comma-separated string rather than an array;
		// the web-login path already accepts both, so this one does too.
		names = strings.Split(v, ",")
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				names = append(names, s)
			}
		}
	case []string:
		names = v
	default:
		log.Debugf("Embedded issuer: group claim %q on external issuer %s is neither a string nor a list",
			detail.GroupClaim, detail.Name)
		return nil
	}

	patterns := make([]*regexp.Regexp, 0, len(detail.GroupAllowPatterns))
	for _, p := range detail.GroupAllowPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			// validateDetail compiles these at configuration time, so a failure
			// here means the row was written around the admin API. Drop the
			// pattern rather than the safety property it was meant to provide.
			log.Warnf("Embedded issuer: external issuer %s has an uncompilable group pattern %q; ignoring it",
				detail.Name, p)
			continue
		}
		patterns = append(patterns, re)
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || len(name) > maxExternalGroupLen {
			continue
		}
		if strings.IndexFunc(name, unicode.IsControl) >= 0 {
			continue
		}
		if len(patterns) > 0 {
			matched := false
			for _, re := range patterns {
				if re.MatchString(name) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		var produced string
		if detail.GroupMode == GroupModeMapped {
			// The mapping is the allow-list: an unmapped assertion contributes
			// nothing. The result is a plain local group name, deliberately
			// unprefixed — the operator already said what it should be.
			local, ok := mapping[name]
			if !ok {
				continue
			}
			produced = local
		} else {
			// The prefix is the trust boundary. Group names are bearer
			// authority — $GROUP in Issuer.AuthorizationTemplates, and the
			// name-keyed lookups behind group scopes — so a foreign name lands
			// in its own namespace unless the operator asked for flat names.
			produced = detail.GroupPrefix + name
		}

		// Final safety net, applied AFTER prefixing/mapping: a foreign token
		// must never contribute a reserved ACL name (the all-authenticated
		// sentinel, or a "user-<username>" personal group). Filtering the
		// produced name — not the raw one — is what makes this hold in flat
		// mode and even when an operator sets a prefix like "user-": either way
		// the result is rejected here rather than impersonating a user's
		// personal grants. A normal prefix ("keycloak:user-victim") is not
		// reserved and passes, correctly namespaced.
		if database.IsReservedACLGroupName(produced) {
			log.Warnf("Embedded issuer: external issuer %s asserted group %q which maps to reserved ACL name %q; dropping it",
				detail.Name, name, produced)
			continue
		}
		out = append(out, produced)
		if len(out) >= maxExternalGroups {
			log.Warnf("Embedded issuer: external issuer %s asserted more than %d groups; truncating",
				detail.Name, maxExternalGroups)
			break
		}
	}
	return out
}

// ResolveExternalGroups produces the group list used to compute the exchanged
// token's authorizations: the foreign token's groups (namespaced) unioned with
// the user's local memberships, per the issuer's configuration.
func ResolveExternalGroups(db *gorm.DB, detail *ExternalIssuerDetail, parsed jwt.Token, user *database.User, mapping map[string]string) ([]string, error) {
	groups := externalGroupsFromClaim(detail, parsed, mapping)

	if detail.IncludeLocalGroups && db != nil && user != nil {
		local, err := database.GetMemberGroups(db, user.ID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load local group memberships")
		}
		for _, g := range local {
			groups = append(groups, g.Name)
		}
	}

	// De-duplicate while preserving order so the token's wlcg.groups claim is
	// stable across exchanges.
	seen := make(map[string]bool, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out, nil
}
