//go:build !windows

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

package condor

import (
	"fmt"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/pkg/errors"
)

// ObjectParamHandler translates one object-typed Pelican parameter from HTCondor
// configuration.
//
// Object-typed parameters are lists of structures, which HTCondor's flat string
// namespace cannot hold directly. Each is expressed as a per-item knob family: a
// list knob naming the items, and per-field knobs beneath each name. See
// knobFamily for the shape.
//
// A handler may instead declare the parameter unsupported in HTCondor mode (see
// Unsupported). Both are deliberate answers; the generated ObjectParamSet
// constructor exists to ensure one of them is always given.
type ObjectParamHandler struct {
	// Param is the Pelican parameter this handler is for, e.g. "Origin.Exports".
	// The generated constructor checks it against the slot it was passed in.
	Param string

	// Decode reads the parameter's items from HTCondor configuration and returns
	// the value to store in viper, or nil when the configuration says nothing
	// about this parameter. Nil for an unsupported parameter.
	Decode func(cfg *config.Config) (any, error)

	// unsupportedReason, when non-empty, records why this parameter has no
	// HTCondor representation.
	unsupportedReason string
}

// Supported reports whether the parameter can be configured in HTCondor mode.
func (h ObjectParamHandler) Supported() bool { return h.unsupportedReason == "" }

// UnsupportedReason explains why an unsupported parameter has no translation.
func (h ObjectParamHandler) UnsupportedReason() string { return h.unsupportedReason }

// Unsupported declares that a parameter has no HTCondor representation, and why.
//
// This is a legitimate outcome, not a placeholder. Several object-typed
// parameters belong to components that cannot run in HTCondor mode at all, and
// inventing knob families for them would be dead configuration surface an
// operator could set and watch do nothing. What matters is that the decision is
// recorded here rather than left implicit.
//
// An operator who has configured such a parameter is told so at startup instead
// of having it silently ignored.
func Unsupported(param, reason string) ObjectParamHandler {
	return ObjectParamHandler{Param: param, unsupportedReason: reason}
}

// objectParams is the complete registry. Adding an object-typed parameter to
// parameters.yaml adds an argument to NewObjectParamSet, so this call stops
// compiling until the new parameter is handled here.
var objectParams = NewObjectParamSet(
	// GeoIPOverrides — director-only, and a list of IP-range-to-coordinates
	// mappings that is far more naturally expressed in YAML than in knob
	// families. A director under condor_master can still be given one through a
	// Pelican configuration file.
	Unsupported("GeoIPOverrides",
		"GeoIP overrides remain in Pelican's own configuration; they have no HTCondor knob family"),

	// Issuer.AuthorizationTemplates — nested scope/action structures whose depth
	// does not map onto a two-level knob family.
	Unsupported("Issuer.AuthorizationTemplates",
		"issuer authorization templates remain in Pelican's own configuration"),

	// Issuer.OIDCAuthenticationRequirements — a list of claim/value pairs bound
	// to the embedded issuer, which is configured alongside the templates above.
	Unsupported("Issuer.OIDCAuthenticationRequirements",
		"issuer OIDC requirements remain in Pelican's own configuration"),

	// LocalCache.StorageDirs — the local cache is the client-side cache, not a
	// server module HTCondor mode runs.
	Unsupported("LocalCache.StorageDirs",
		"the local cache is not a server module and is not run under condor_master"),

	// Lotman.PolicyDefinitions — Lotman is part of the XRootD-based cache, which
	// HTCondor mode excludes by design (§2.2).
	Unsupported("Lotman.PolicyDefinitions",
		"Lotman belongs to the XRootD cache, which is out of scope in HTCondor mode"),

	newOriginExportsHandler(),

	// Registry.CustomRegistrationFields — free-form web-form definitions,
	// authored as YAML and edited alongside the registry's other web content.
	Unsupported("Registry.CustomRegistrationFields",
		"custom registration fields remain in Pelican's own configuration"),

	// Registry.Institutions — a list of name/ID pairs commonly generated from an
	// external source and pointed at by Registry.InstitutionsUrl instead.
	Unsupported("Registry.Institutions",
		"institutions remain in Pelican's own configuration, or are fetched via Registry.InstitutionsUrl"),

	// Shoveler.IPMapping — belongs to the XRootD monitoring shoveler; HTCondor
	// mode records transfers through the ClassAd archive instead (§7).
	Unsupported("Shoveler.IPMapping",
		"shoveler IP mapping remains in Pelican's own configuration"),
)

// originExport is one entry of Origin.Exports, in the subset of fields a native
// (non-XRootD) origin uses.
type originExport struct {
	FederationPrefix string   `mapstructure:"FederationPrefix"`
	StoragePrefix    string   `mapstructure:"StoragePrefix"`
	Capabilities     []string `mapstructure:"Capabilities"`
}

// newOriginExportsHandler translates Origin.Exports from a knob family:
//
//	PELICAN_ORIGIN_EXPORTS = public, protected
//	PELICAN_ORIGIN_EXPORT_PUBLIC_FEDERATIONPREFIX = /ospool/public
//	PELICAN_ORIGIN_EXPORT_PUBLIC_STORAGEPREFIX    = /data/public
//	PELICAN_ORIGIN_EXPORT_PUBLIC_CAPABILITIES     = PublicReads, Reads
//
// The list knob is authoritative about which exports exist, rather than the set
// being inferred by scanning for PELICAN_ORIGIN_EXPORT_* prefixes. An export
// that is half-written or commented out is then simply inert, instead of being
// silently activated, and the translator has a definite list to validate
// against.
func newOriginExportsHandler() ObjectParamHandler {
	return ObjectParamHandler{
		Param: "Origin.Exports",
		Decode: func(cfg *config.Config) (any, error) {
			items := knobList(cfg, "PELICAN_ORIGIN_EXPORTS")
			if len(items) == 0 {
				return nil, nil
			}
			exports := make([]originExport, 0, len(items))
			for _, item := range items {
				prefix := fmt.Sprintf("PELICAN_ORIGIN_EXPORT_%s", knobToken(item))
				export := originExport{
					FederationPrefix: knobString(cfg, prefix+"_FEDERATIONPREFIX"),
					StoragePrefix:    knobString(cfg, prefix+"_STORAGEPREFIX"),
					Capabilities:     knobList(cfg, prefix+"_CAPABILITIES"),
				}
				if export.FederationPrefix == "" {
					return nil, errors.Errorf(
						"export %q is missing %s_FEDERATIONPREFIX", item, prefix)
				}
				if export.StoragePrefix == "" {
					return nil, errors.Errorf(
						"export %q is missing %s_STORAGEPREFIX", item, prefix)
				}
				exports = append(exports, export)
			}
			return exports, nil
		},
	}
}
