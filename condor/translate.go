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
	"sort"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	pelicanconfig "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// SourceCondorConfig marks a configuration value as having come from HTCondor's
// configuration rather than a Pelican file or environment variable, so
// `pelican config dump` and the config page in the web UI report where a value
// actually came from. Precedence that an operator cannot see is precedence they
// will eventually file a bug about.
const SourceCondorConfig pelicanconfig.ConfigSourceType = "condor-config"

// ParamKnob returns the HTCondor configuration knob that sets a Pelican
// parameter: the parameter name upper-cased with dots replaced by underscores,
// prefixed PELICAN_. Cache.EnableV2 becomes PELICAN_CACHE_ENABLEV2.
//
// This is deliberately the same spelling as the parameter's environment
// variable. Operators already know the mapping, the documentation generator
// already emits it, and there is no second table to drift out of sync with the
// parameter list.
func ParamKnob(paramName string) string {
	return "PELICAN_" + strings.ToUpper(strings.ReplaceAll(paramName, ".", "_"))
}

// RegisterConfigProvider installs the HTCondor configuration layer.
//
// It must be called before Pelican's configuration is loaded; Serve does so.
// The provider is a no-op when cfg is nil, which keeps a caller that could not
// read the pool configuration from silently getting an empty layer.
func RegisterConfigProvider(cfg *config.Config, modules server_structs.ServerType) {
	if cfg == nil {
		return
	}
	pelicanconfig.RegisterExternalConfigProvider(func(v *viper.Viper) error {
		if err := applyCondorConfig(v, cfg); err != nil {
			return err
		}
		// Validated here rather than at startup because this is the first moment
		// Pelican's configuration exists (§4.1): the storage type is only
		// knowable once the config files have been merged.
		return validateNativeBackends(v, modules)
	})
}

// validateNativeBackends refuses a configuration HTCondor mode cannot serve.
//
// §2.2 excludes XRootD: the daemon is a single process with no children, which
// is what lets the DaemonCore contract fit. A configuration asking for an
// XRootD-backed origin or the XRootD cache would otherwise start and then try to
// launch XRootD, failing later and further from the cause. Refusing here, with
// the native alternative named, is the difference between a configuration error
// and a mystery.
func validateNativeBackends(v *viper.Viper, modules server_structs.ServerType) error {
	if modules.IsEnabled(server_structs.OriginType) {
		storageType := v.GetString("Origin.StorageType")
		if server_structs.OriginStorageType(storageType).UsesXRootD() {
			return errors.Errorf(
				"Origin.StorageType %q is backed by XRootD, which is not supported under condor_master; "+
					"use a native backend instead (posixv2, s3v2, httpsv2, globusv2 or ssh)",
				storageType)
		}
	}
	if modules.IsEnabled(server_structs.CacheType) && !v.GetBool("Cache.EnableV2") {
		return errors.New(
			"the XRootD-based cache is not supported under condor_master; " +
				"set Cache.EnableV2 (PELICAN_CACHE_ENABLEV2 = true) to use the native cache")
	}
	return nil
}

// applyCondorConfig merges every Pelican parameter that HTCondor configuration
// sets into viper.
//
// Values are merged as strings into viper's config layer, exactly as environment
// variables arrive: viper's decode hooks already turn strings into bools, ints,
// durations and slices, so no per-parameter type table is needed here -- and one
// would be another thing to keep in step with parameters.yaml.
//
// Object-typed parameters cannot be expressed as a single string and are handled
// by their registered knob-family handlers instead (see object_params.go).
func applyCondorConfig(v *viper.Viper, cfg *config.Config) error {
	settings := map[string]any{}
	tracker := pelicanconfig.GetSourceTracker()

	objectNames := map[string]bool{}
	for _, name := range ObjectParamNames {
		objectNames[name] = true
	}

	for _, name := range param.AllParameterNames() {
		if objectNames[name] {
			continue // handled below, from a knob family
		}
		knob := ParamKnob(name)
		value, ok := cfg.Get(knob)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			// An explicitly blank knob means "unset"; merging an empty string
			// would override a good default with nothing.
			continue
		}
		settings[name] = value
		tracker.Record(name, pelicanconfig.ConfigSource{Type: SourceCondorConfig, Detail: knob})
	}

	for _, name := range ObjectParamNames {
		handler, ok := objectParams.Handler(name)
		if !ok {
			// Unreachable: the generated constructor guarantees a handler exists.
			return errors.Errorf("no HTCondor handler for object parameter %s", name)
		}
		if !handler.Supported() {
			warnIfUnsupportedIsConfigured(cfg, name, handler)
			continue
		}
		decoded, err := handler.Decode(cfg)
		if err != nil {
			return errors.Wrapf(err, "invalid HTCondor configuration for %s", name)
		}
		if decoded == nil {
			continue
		}
		settings[name] = decoded
		tracker.Record(name, pelicanconfig.ConfigSource{
			Type: SourceCondorConfig, Detail: ParamKnob(name) + " (knob family)"})
	}

	// Fill in Pelican's file locations from the pool's directory layout, for
	// anything the operator has not chosen themselves.
	derived := applyDerivedPaths(cfg, settings)
	for _, name := range derived {
		log.Debugf("%s derived from HTCondor's directory layout: %v", name, settings[name])
	}

	if len(settings) == 0 {
		log.Debug("HTCondor configuration set no Pelican parameters")
		return nil
	}

	if err := v.MergeConfigMap(nest(settings)); err != nil {
		return errors.Wrap(err, "failed to merge HTCondor configuration into Pelican's")
	}
	log.Infof("Applied %d Pelican parameter(s) from HTCondor configuration (%d derived from its directory layout)",
		len(settings), len(derived))
	return nil
}

// warnIfUnsupportedIsConfigured tells an operator when they have configured an
// object-typed parameter that HTCondor mode cannot translate.
//
// The parameter has no knob family by definition, so the only thing to look for
// is the list knob an operator would reach for first. Getting a warning is the
// whole point of recording a reason on an unsupported handler: the alternative
// is a setting that is silently ignored.
func warnIfUnsupportedIsConfigured(cfg *config.Config, name string, handler ObjectParamHandler) {
	if knobString(cfg, ParamKnob(name)) == "" {
		return
	}
	log.Warnf("%s is set in HTCondor configuration but is not supported in HTCondor mode: %s",
		ParamKnob(name), handler.UnsupportedReason())
}

// nest turns flat dotted keys into the nested maps viper's config layer holds.
// MergeConfigMap merges into that layer -- the same one a config file populates
// -- so the shape has to match, and a flat "Origin.Exports" key would otherwise
// be stored as a literal key with a dot in it and never found by a lookup of
// Origin -> Exports.
//
// Keys are lower-cased because viper is case-insensitive and normalizes to lower
// case internally; a nested map merged with mixed case would not be found.
func nest(flat map[string]any) map[string]any {
	root := map[string]any{}
	for key, value := range flat {
		parts := strings.Split(strings.ToLower(key), ".")
		node := root
		for _, part := range parts[:len(parts)-1] {
			next, ok := node[part].(map[string]any)
			if !ok {
				next = map[string]any{}
				node[part] = next
			}
			node = next
		}
		node[parts[len(parts)-1]] = value
	}
	return root
}

// Reapply re-reads HTCondor configuration and applies what can change at
// runtime, returning what it changed and what it could not.
//
// This is condor_reconfig doing something rather than only logging. Pelican
// already has a hot-reload mechanism -- param.MultiSet rebuilds the cached
// configuration and fires the callbacks modules register with
// param.RegisterCallback, which is how the logging subsystem picks up a level
// change -- so a reconfigure feeds that rather than inventing a parallel path.
//
// Only parameters Pelican marks runtime-configurable are applied. The rest are
// reported by name, because a daemon that silently applied half a configuration
// would be in a state matching neither the old nor the new one, and an operator
// who ran condor_reconfig deserves to know a restart is still needed.
//
// Object-typed parameters are not reapplied: they describe structure -- exports,
// storage backends -- that the modules bound at startup, so changing them at
// runtime would need those modules to be rebuilt, not just re-read.
func Reapply(cfg *config.Config) (applied, deferred []string, err error) {
	if cfg == nil {
		return nil, nil, nil
	}

	updates := map[string]any{}
	objectNames := map[string]bool{}
	for _, name := range ObjectParamNames {
		objectNames[name] = true
	}

	for _, name := range param.AllParameterNames() {
		if objectNames[name] {
			continue
		}
		value, ok := cfg.Get(ParamKnob(name))
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" || value == viper.GetString(name) {
			continue // unset, or unchanged
		}
		if !param.IsRuntimeConfigurable(name) {
			deferred = append(deferred, name)
			continue
		}
		updates[name] = value
		applied = append(applied, name)
	}

	sort.Strings(applied)
	sort.Strings(deferred)

	if len(updates) > 0 {
		if err := param.MultiSet(updates); err != nil {
			return nil, deferred, errors.Wrap(err, "failed to apply the reloaded HTCondor configuration")
		}
		for _, name := range applied {
			pelicanconfig.GetSourceTracker().Record(name, pelicanconfig.ConfigSource{
				Type: SourceCondorConfig, Detail: ParamKnob(name)})
		}
	}
	return applied, deferred, nil
}
