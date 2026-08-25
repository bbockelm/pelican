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
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/database"
)

// Group-mapping modes for an external issuer.
const (
	// GroupModeIgnore discards the foreign token's group claim entirely.
	GroupModeIgnore = "ignore"
	// GroupModeClaim reads groups from the token's configured group claim,
	// filters them, and namespaces them behind the issuer's GroupPrefix.
	GroupModeClaim = "claim"
	// GroupModeMapped resolves foreign group names through an explicit
	// mapping table. Reserved; not implemented (see the design doc's phasing).
	GroupModeMapped = "mapped"
)

// defaultAllowedAlgorithms is the signing-algorithm allow-list applied to a
// subject token when an issuer record does not narrow it further.
//
// Asymmetric only, and deliberately so: a verifier that accepts an HMAC
// algorithm while holding the issuer's *public* JWKS can be induced to verify
// an attacker-signed token using a public key as the shared secret. There is
// no legitimate reason for a remote issuer's tokens to be HMAC-signed here, so
// the family is excluded outright rather than guarded case by case.
var defaultAllowedAlgorithms = []string{"RS256", "ES256", "PS256"}

// permittedAlgorithms is every algorithm an operator is allowed to configure.
var permittedAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// defaultUsernameClaims mirrors the candidate order the web-login path uses
// when bootstrapping a username from IdP claims (see web_ui/oauth2_client.go).
var defaultUsernameClaims = []string{"preferred_username", "email", "nickname"}

// ExternalIssuerDetail is the decoded, API-facing view of an
// ExternalIssuerRecord. It is what the admin REST endpoints, the CLI, and the
// web UI exchange; the record's JSON-encoded TEXT columns never escape the
// storage layer.
type ExternalIssuerDetail struct {
	// Name is the stable identifier — the config key and the value referenced
	// by probe/dry-run. External issuers are defined in configuration
	// (Origin.Exports[*].ExternalIssuers or the global Issuer.ExternalIssuers),
	// not in the database, so there is no generated id.
	Name      string `json:"name"`
	IssuerURL string `json:"issuer_url"`
	JWKSURL   string `json:"jwks_url,omitempty"`
	Enabled   bool   `json:"enabled"`

	RequiredAudiences []string          `json:"required_audiences"`
	AllowAnyAudience  bool              `json:"allow_any_audience"`
	RequiredScopes    []string          `json:"required_scopes"`
	RequiredClaims    map[string]string `json:"required_claims"`
	AllowedAlgorithms []string          `json:"allowed_algorithms"`

	SubjectClaim   string   `json:"subject_claim"`
	UsernameClaims []string `json:"username_claims"`
	AutoEnroll     bool     `json:"auto_enroll"`

	GroupClaim         string   `json:"group_claim"`
	GroupMode          string   `json:"group_mode"`
	GroupPrefix        string   `json:"group_prefix"`
	AllowFlatGroups    bool     `json:"allow_flat_groups"`
	GroupAllowPatterns []string `json:"group_allow_patterns"`
	IncludeLocalGroups bool     `json:"include_local_groups"`

	// GroupMappings is the external->local group table used when GroupMode is
	// "mapped". Configured inline on the issuer rather than in a side table.
	GroupMappings map[string]string `json:"group_mappings,omitempty"`

	AllowRefresh            bool  `json:"allow_refresh"`
	MaxTokenLifetimeSeconds int64 `json:"max_token_lifetime_seconds"`
}

// ExternalIssuerInput carries a create or a partial update. Every field is a
// pointer so that "omitted" is distinguishable from "explicitly set to the
// zero value" — the same convention ClientUpdate uses, extended to booleans
// because several of them (AutoEnroll, IncludeLocalGroups, Enabled) default to
// true and so cannot be defaulted from a bare false.
type ExternalIssuerInput struct {
	Name      *string `json:"name"`
	IssuerURL *string `json:"issuer_url"`
	JWKSURL   *string `json:"jwks_url"`
	Enabled   *bool   `json:"enabled"`

	RequiredAudiences *[]string          `json:"required_audiences"`
	AllowAnyAudience  *bool              `json:"allow_any_audience"`
	RequiredScopes    *[]string          `json:"required_scopes"`
	RequiredClaims    *map[string]string `json:"required_claims"`
	AllowedAlgorithms *[]string          `json:"allowed_algorithms"`

	SubjectClaim   *string   `json:"subject_claim"`
	UsernameClaims *[]string `json:"username_claims"`
	AutoEnroll     *bool     `json:"auto_enroll"`

	GroupClaim         *string   `json:"group_claim"`
	GroupMode          *string   `json:"group_mode"`
	GroupPrefix        *string   `json:"group_prefix"`
	AllowFlatGroups    *bool     `json:"allow_flat_groups"`
	GroupAllowPatterns *[]string `json:"group_allow_patterns"`
	IncludeLocalGroups *bool     `json:"include_local_groups"`

	GroupMappings *map[string]string `json:"group_mappings"`

	AllowRefresh            *bool  `json:"allow_refresh"`
	MaxTokenLifetimeSeconds *int64 `json:"max_token_lifetime_seconds"`
}

// NormalizeIssuerURL trims a single trailing slash so that "https://kc/realms/p"
// and "https://kc/realms/p/" are the same trust anchor.
//
// Normalization stops there on purpose. Matching against a stored issuer is
// exact string equality — no case folding, no host-only comparison, no prefix
// matching — because every relaxation of that rule is a way for a lookalike
// issuer URL to be accepted as a trusted one.
func NormalizeIssuerURL(raw string) string {
	return strings.TrimSuffix(strings.TrimSpace(raw), "/")
}

// validateIssuerURL enforces that a trust anchor is an absolute https URL.
// http is tolerated only for loopback, which keeps test fixtures workable
// without opening a door to plaintext discovery against a real IdP.
func validateIssuerURL(raw, field string) error {
	if raw == "" {
		return errors.Errorf("%s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.Wrapf(err, "%s is not a valid URL", field)
	}
	if u.Host == "" {
		return errors.Errorf("%s must be an absolute URL", field)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return errors.Errorf("%s must use https (http is permitted only for loopback addresses)", field)
	default:
		return errors.Errorf("%s must use the https scheme", field)
	}
}

// applyInput merges an input onto a detail, filling create-time defaults for
// anything still unset, and then validates the result. It is shared by create
// and update so the two cannot enforce different rules.
//
// isCreate controls defaulting only. On create, an omitted field takes its
// default; on update, an omitted field keeps the stored value. The distinction
// matters most for GroupPrefix: an operator who deliberately configured flat
// group names must not have the default prefix silently reinstated by an
// unrelated edit, and an operator who explicitly sends an empty prefix must be
// refused rather than quietly given the default.
func applyInput(d *ExternalIssuerDetail, in ExternalIssuerInput, isCreate bool) error {
	prefixExplicit := in.GroupPrefix != nil
	if in.Name != nil {
		d.Name = strings.TrimSpace(*in.Name)
	}
	if in.IssuerURL != nil {
		d.IssuerURL = NormalizeIssuerURL(*in.IssuerURL)
	}
	if in.JWKSURL != nil {
		d.JWKSURL = strings.TrimSpace(*in.JWKSURL)
	}
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	if in.RequiredAudiences != nil {
		d.RequiredAudiences = *in.RequiredAudiences
	}
	if in.AllowAnyAudience != nil {
		d.AllowAnyAudience = *in.AllowAnyAudience
	}
	if in.RequiredScopes != nil {
		d.RequiredScopes = *in.RequiredScopes
	}
	if in.RequiredClaims != nil {
		d.RequiredClaims = *in.RequiredClaims
	}
	if in.AllowedAlgorithms != nil {
		d.AllowedAlgorithms = *in.AllowedAlgorithms
	}
	if in.SubjectClaim != nil {
		d.SubjectClaim = strings.TrimSpace(*in.SubjectClaim)
	}
	if in.UsernameClaims != nil {
		d.UsernameClaims = *in.UsernameClaims
	}
	if in.AutoEnroll != nil {
		d.AutoEnroll = *in.AutoEnroll
	}
	if in.GroupClaim != nil {
		d.GroupClaim = strings.TrimSpace(*in.GroupClaim)
	}
	if in.GroupMode != nil {
		d.GroupMode = strings.ToLower(strings.TrimSpace(*in.GroupMode))
	}
	if in.GroupPrefix != nil {
		d.GroupPrefix = *in.GroupPrefix
	}
	if in.AllowFlatGroups != nil {
		d.AllowFlatGroups = *in.AllowFlatGroups
	}
	if in.GroupAllowPatterns != nil {
		d.GroupAllowPatterns = *in.GroupAllowPatterns
	}
	if in.IncludeLocalGroups != nil {
		d.IncludeLocalGroups = *in.IncludeLocalGroups
	}
	if in.AllowRefresh != nil {
		d.AllowRefresh = *in.AllowRefresh
	}
	if in.MaxTokenLifetimeSeconds != nil {
		d.MaxTokenLifetimeSeconds = *in.MaxTokenLifetimeSeconds
	}
	if in.GroupMappings != nil {
		d.GroupMappings = *in.GroupMappings
	}

	// Create-time defaults for anything still unset.
	if d.SubjectClaim == "" {
		d.SubjectClaim = "sub"
	}
	if d.GroupClaim == "" {
		d.GroupClaim = "groups"
	}
	if d.GroupMode == "" {
		d.GroupMode = GroupModeClaim
	}
	if len(d.AllowedAlgorithms) == 0 {
		d.AllowedAlgorithms = append([]string(nil), defaultAllowedAlgorithms...)
	}
	if len(d.UsernameClaims) == 0 {
		d.UsernameClaims = append([]string(nil), defaultUsernameClaims...)
	}
	// An *omitted* group prefix defaults to the issuer's name, which is what
	// makes foreign group names land in their own namespace ("keycloak:cms")
	// instead of competing with local ones. An explicitly empty prefix is not
	// defaulted — it falls through to validateDetail, which refuses it unless
	// AllowFlatGroups says the operator meant it.
	if isCreate && !prefixExplicit && d.GroupPrefix == "" && d.Name != "" && d.GroupMode == GroupModeClaim {
		d.GroupPrefix = d.Name + ":"
	}
	if d.RequiredClaims == nil {
		d.RequiredClaims = map[string]string{}
	}
	if d.RequiredAudiences == nil {
		d.RequiredAudiences = []string{}
	}
	if d.RequiredScopes == nil {
		d.RequiredScopes = []string{}
	}
	if d.GroupAllowPatterns == nil {
		d.GroupAllowPatterns = []string{}
	}

	return validateDetail(d)
}

// validateDetail enforces every configuration-time invariant. The two rules
// that are easy to mistake for pedantry — a non-empty audience list and a
// non-empty group prefix — are the ones that keep a trusted IdP from being a
// blanket authorization oracle; both can be waived, but only deliberately.
func validateDetail(d *ExternalIssuerDetail) error {
	if d.Name == "" {
		return errors.New("name is required")
	}
	if err := database.ValidateIdentifier(d.Name); err != nil {
		return errors.Wrap(err, "name is not a valid identifier")
	}
	if err := validateIssuerURL(d.IssuerURL, "issuer_url"); err != nil {
		return err
	}
	if d.JWKSURL != "" {
		if err := validateIssuerURL(d.JWKSURL, "jwks_url"); err != nil {
			return err
		}
	}
	if d.SubjectClaim == "" {
		return errors.New("subject_claim is required")
	}

	switch d.GroupMode {
	case GroupModeIgnore, GroupModeClaim, GroupModeMapped:
	default:
		return errors.Errorf("group_mode must be one of \"ignore\", \"claim\", or \"mapped\" (got %q)", d.GroupMode)
	}

	for _, alg := range d.AllowedAlgorithms {
		if !permittedAlgorithms[alg] {
			return errors.Errorf("allowed_algorithms contains %q; only asymmetric JWS algorithms are permitted (%s)",
				alg, "RS256/384/512, ES256/384/512, PS256/384/512")
		}
	}
	if len(d.AllowedAlgorithms) == 0 {
		return errors.New("allowed_algorithms must not be empty")
	}

	if len(d.RequiredAudiences) == 0 && !d.AllowAnyAudience {
		return errors.New("required_audiences must not be empty: without it, every token this issuer mints for any of its clients would be accepted here. Set allow_any_audience=true to accept that risk deliberately")
	}
	if len(d.RequiredAudiences) > 0 && d.AllowAnyAudience {
		return errors.New("allow_any_audience is incompatible with a non-empty required_audiences")
	}

	if d.GroupMode == GroupModeMapped {
		if d.GroupClaim == "" {
			return errors.New("group_claim is required when group_mode is \"mapped\"")
		}
		// A mapped name is used verbatim as a local group name, so each must be
		// a valid, non-reserved identifier — mapping to "user-victim" would hand
		// the foreign issuer that user's personal grants.
		for ext, local := range d.GroupMappings {
			if ext == "" || local == "" {
				return errors.New("group_mappings entries must have non-empty keys and values")
			}
			if err := database.ValidateIdentifier(local); err != nil {
				return errors.Wrapf(err, "group_mappings target %q is not a valid group name", local)
			}
			if database.IsReservedACLGroupName(local) {
				return errors.Errorf("group_mappings target %q is a reserved ACL name", local)
			}
		}
	}
	if d.GroupMode == GroupModeClaim {
		if d.GroupClaim == "" {
			return errors.New("group_claim is required when group_mode is \"claim\"")
		}
		// A prefix that lands foreign names in the personal-group namespace
		// ("user-...") would let the IdP impersonate any user's personal ACL
		// grants. Ingestion drops such names anyway, but rejecting the prefix
		// here turns a silently-useless config into a clear error.
		if database.IsReservedACLGroupName(d.GroupPrefix) || database.IsReservedACLGroupName(d.GroupPrefix+"x") {
			return errors.Errorf("group_prefix %q collides with a reserved ACL namespace (\"user-\" personal groups or the all-authenticated sentinel); choose a different prefix", d.GroupPrefix)
		}
		if d.GroupPrefix == "" && !d.AllowFlatGroups {
			return errors.New("group_prefix must not be empty: group names are bearer authority in Issuer.AuthorizationTemplates, so foreign groups are namespaced by default. Set allow_flat_groups=true to use unprefixed names deliberately")
		}
	}

	for _, pat := range d.GroupAllowPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			return errors.Wrapf(err, "group_allow_patterns entry %q is not a valid regular expression", pat)
		}
	}

	if d.MaxTokenLifetimeSeconds < 0 {
		return errors.New("max_token_lifetime_seconds must not be negative")
	}
	return nil
}

// ---- configuration parsing ----

// ParseExternalIssuers decodes and validates a list of external-issuer
// configuration entries (from Origin.Exports[*].ExternalIssuers or the global
// Issuer.ExternalIssuers). Each entry is decoded like a create request and run
// through the same applyInput/validateDetail path the API used, so a bad
// configuration fails loudly at startup with the same messages — and the two
// deliberately-dangerous acknowledgments (AllowAnyAudience, AllowFlatGroups)
// become explicit, git-reviewed fields rather than database booleans.
//
// Config keys are the Go field names (CamelCase): IssuerURL, RequiredAudiences,
// GroupMode, GroupPrefix, GroupMappings, and so on. mapstructure matches them
// case-insensitively.
func ParseExternalIssuers(raw []interface{}) ([]ExternalIssuerDetail, error) {
	out := make([]ExternalIssuerDetail, 0, len(raw))
	seenNames := map[string]bool{}
	seenURLs := map[string]bool{}
	for idx, entry := range raw {
		var in ExternalIssuerInput
		dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			Result:           &in,
			WeaklyTypedInput: true,
			ErrorUnused:      true,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to build the external-issuer config decoder")
		}
		if err := dec.Decode(entry); err != nil {
			return nil, errors.Wrapf(err, "external issuer #%d is not valid configuration", idx+1)
		}

		// Config entries are always fully-specified "creates": Enabled defaults
		// true unless set false, matching the runtime default.
		detail := &ExternalIssuerDetail{Enabled: true, AutoEnroll: true, IncludeLocalGroups: true}
		if in.Enabled != nil {
			detail.Enabled = *in.Enabled
		}
		if err := applyInput(detail, in, true); err != nil {
			label := detail.Name
			if label == "" {
				label = "#" + strconv.Itoa(idx+1)
			}
			return nil, errors.Wrapf(err, "external issuer %s is misconfigured", label)
		}

		if seenNames[detail.Name] {
			return nil, errors.Errorf("duplicate external issuer name %q", detail.Name)
		}
		if seenURLs[detail.IssuerURL] {
			return nil, errors.Errorf("duplicate external issuer URL %q", detail.IssuerURL)
		}
		seenNames[detail.Name] = true
		seenURLs[detail.IssuerURL] = true
		out = append(out, *detail)
	}
	return out, nil
}

// ExternalIssuerByURL resolves a subject token's issuer to a configured,
// enabled external issuer, or nil. Matching is exact string equality after
// trailing-slash normalization — the same trust-anchor rule the storage lookup
// used, now against the in-memory config list. Disabled issuers are treated as
// absent.
func ExternalIssuerByURL(issuers []ExternalIssuerDetail, issuerURL string) *ExternalIssuerDetail {
	norm := NormalizeIssuerURL(issuerURL)
	for i := range issuers {
		if issuers[i].Enabled && issuers[i].IssuerURL == norm {
			return &issuers[i]
		}
	}
	return nil
}

// ExternalIssuerByName looks a configured issuer up by its name (used by the
// read-only probe and dry-run diagnostics).
func ExternalIssuerByName(issuers []ExternalIssuerDetail, name string) *ExternalIssuerDetail {
	for i := range issuers {
		if issuers[i].Name == name {
			return &issuers[i]
		}
	}
	return nil
}
