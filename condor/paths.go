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
	"path/filepath"

	"github.com/bbockelm/golang-htcondor/config"

	pelicanconfig "github.com/pelicanplatform/pelican/config"
)

// derivedPath is a Pelican parameter whose value follows the pool's directory
// layout when the operator has not chosen one.
type derivedPath struct {
	// Param is the Pelican parameter to supply.
	Param string
	// From builds the value from HTCondor configuration, returning "" to decline.
	From func(cfg *config.Config) string
	// Why explains the choice, for the debug log an operator reads when a file
	// is not where they expected.
	Why string
}

// derivedPaths places Pelican's files where an HTCondor administrator expects a
// daemon's files to be, following the pool's own directory layout rather than
// Pelican's.
//
// These are defaults, not overrides. Unlike an explicit PELICAN_* knob -- which
// is an instruction and outranks Pelican's configuration files -- a derived path
// is only a better guess than Pelican's built-in default, so it applies solely
// where the operator has expressed no preference. applyDerivedPaths enforces
// that distinction using the source tracker.
//
// Databases go under $(SPOOL) rather than $(LOCAL_DIR) because SPOOL is
// HTCondor's directory for state that must survive a restart, which is exactly
// what these are. Runtime state goes under $(RUN), which is the pool's directory
// for things that need not.
var derivedPaths = []derivedPath{
	{
		Param: "Logging.LogLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "LOG", "PelicanLog") },
		Why:   "a daemon's log belongs in the pool's log directory",
	},
	{
		Param: "RuntimeDir",
		From:  func(cfg *config.Config) string { return under(cfg, "RUN", "pelican") },
		Why:   "runtime state belongs in the pool's run directory",
	},
	{
		Param: "Server.DbLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "SPOOL", "pelican", "server.sqlite") },
		Why:   "databases belong in the pool's spool directory, which survives a restart",
	},
	{
		Param: "Director.DbLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "SPOOL", "pelican", "director.sqlite") },
		Why:   "databases belong in the pool's spool directory, which survives a restart",
	},
	{
		Param: "Registry.DbLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "SPOOL", "pelican", "registry.sqlite") },
		Why:   "databases belong in the pool's spool directory, which survives a restart",
	},
	{
		Param: "Origin.DbLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "SPOOL", "pelican", "origin.sqlite") },
		Why:   "databases belong in the pool's spool directory, which survives a restart",
	},
	{
		Param: "Cache.DbLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "SPOOL", "pelican", "cache.sqlite") },
		Why:   "databases belong in the pool's spool directory, which survives a restart",
	},
	{
		Param: "Cache.StorageLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "LOCAL_DIR", "pelican-cache") },
		Why:   "cached data is bulk local storage, not spooled state",
	},
	{
		Param: "Monitoring.DataLocation",
		From:  func(cfg *config.Config) string { return under(cfg, "SPOOL", "pelican", "monitoring") },
		Why:   "monitoring data belongs in the pool's spool directory",
	},
	{
		// Not a path, but the same rule: the pool already knows the host's name,
		// and a Pelican that disagreed with it would advertise an address the
		// pool cannot resolve.
		Param: "Server.Hostname",
		From:  func(cfg *config.Config) string { return knobString(cfg, "FULL_HOSTNAME") },
		Why:   "the pool's idea of this host's name",
	},
}

// under joins a path beneath an HTCondor directory knob, returning "" when the
// knob is unset so the caller declines rather than producing a relative path
// rooted at nothing.
func under(cfg *config.Config, knob string, elems ...string) string {
	base := knobString(cfg, knob)
	if base == "" {
		return ""
	}
	return filepath.Join(append([]string{base}, elems...)...)
}

// applyDerivedPaths adds the pool-derived defaults to settings, skipping any
// parameter the operator has already spoken for.
//
// "Already spoken for" means the source tracker attributes the value to
// something other than Pelican's own defaults -- a configuration file, or an
// explicit knob applied earlier in this same pass. Environment variables are
// recorded after this runs, but they outrank the config layer at read time
// anyway, so supplying a default one of them overrides is harmless.
func applyDerivedPaths(cfg *config.Config, settings map[string]any) []string {
	if cfg == nil {
		return nil
	}
	tracker := pelicanconfig.GetSourceTracker()
	applied := []string{}

	for _, dp := range derivedPaths {
		if _, taken := settings[dp.Param]; taken {
			continue // an explicit PELICAN_* knob in this same pass
		}
		if src, ok := tracker.Get(dp.Param); ok && src.Type != pelicanconfig.SourceDefault {
			continue // the operator chose a value in a configuration file
		}
		value := dp.From(cfg)
		if value == "" {
			continue
		}
		settings[dp.Param] = value
		tracker.Record(dp.Param, pelicanconfig.ConfigSource{
			Type: SourceCondorConfig, Detail: "derived: " + dp.Why})
		applied = append(applied, dp.Param)
	}
	return applied
}
