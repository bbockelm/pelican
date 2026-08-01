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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pelicanconfig "github.com/pelicanplatform/pelican/config"
)

const poolLayout = `
LOCAL_DIR = /var/lib/condor
LOG = /var/log/condor
SPOOL = /var/lib/condor/spool
RUN = /var/run/condor
FULL_HOSTNAME = origin.example.org
`

func TestDerivedPathsFollowThePoolLayout(t *testing.T) {
	pelicanconfig.GetSourceTracker().Reset()
	settings := map[string]any{}
	applied := applyDerivedPaths(configFrom(t, poolLayout), settings)
	require.NotEmpty(t, applied)

	assert.Equal(t, "/var/log/condor/PelicanLog", settings["Logging.LogLocation"])
	assert.Equal(t, "/var/run/condor/pelican", settings["RuntimeDir"])
	assert.Equal(t, "/var/lib/condor/spool/pelican/director.sqlite", settings["Director.DbLocation"])
	assert.Equal(t, "/var/lib/condor/spool/pelican/registry.sqlite", settings["Registry.DbLocation"])
	assert.Equal(t, "/var/lib/condor/pelican-cache", settings["Cache.StorageLocation"])
	assert.Equal(t, "origin.example.org", settings["Server.Hostname"])
}

// TestDerivedPathsYieldToTheOperator is the property that separates a derived
// path from an explicit knob: a derived path is only a better guess than
// Pelican's built-in default, so anything the operator actually chose wins.
func TestDerivedPathsYieldToTheOperator(t *testing.T) {
	t.Run("an explicit knob in the same pass", func(t *testing.T) {
		pelicanconfig.GetSourceTracker().Reset()
		settings := map[string]any{"Logging.LogLocation": "/chosen/by/knob.log"}
		applyDerivedPaths(configFrom(t, poolLayout), settings)
		assert.Equal(t, "/chosen/by/knob.log", settings["Logging.LogLocation"])
	})

	t.Run("a value from a Pelican config file", func(t *testing.T) {
		tracker := pelicanconfig.GetSourceTracker()
		tracker.Reset()
		tracker.Record("Logging.LogLocation", pelicanconfig.ConfigSource{
			Type:   pelicanconfig.SourceConfigFile,
			Detail: "/etc/pelican/pelican.yaml",
		})

		settings := map[string]any{}
		applyDerivedPaths(configFrom(t, poolLayout), settings)
		assert.NotContains(t, settings, "Logging.LogLocation",
			"a path set in a Pelican config file must not be overridden by the pool layout")
	})

	t.Run("but a Pelican default does not count as a choice", func(t *testing.T) {
		tracker := pelicanconfig.GetSourceTracker()
		tracker.Reset()
		tracker.Record("Logging.LogLocation", pelicanconfig.ConfigSource{Type: pelicanconfig.SourceDefault})

		settings := map[string]any{}
		applyDerivedPaths(configFrom(t, poolLayout), settings)
		assert.Equal(t, "/var/log/condor/PelicanLog", settings["Logging.LogLocation"],
			"a built-in default is exactly what the pool layout should replace")
	})
}

// TestDerivedPathsDeclineWithoutTheKnob checks that a missing directory knob
// produces no value rather than a path rooted at nothing.
func TestDerivedPathsDeclineWithoutTheKnob(t *testing.T) {
	pelicanconfig.GetSourceTracker().Reset()
	settings := map[string]any{}
	// A configuration with no directory knobs at all. golang-htcondor supplies
	// defaults for LOG/SPOOL/RUN, so only FULL_HOSTNAME is genuinely absent here.
	applyDerivedPaths(configFrom(t, "FULL_HOSTNAME =\n"), settings)
	assert.NotContains(t, settings, "Server.Hostname",
		"a blank knob should be declined, not turned into an empty hostname")
}

func TestUnderDeclinesOnMissingKnob(t *testing.T) {
	cfg := configFrom(t, "SOMEWHERE = /tmp/x\n")
	assert.Equal(t, "/tmp/x/a/b", under(cfg, "SOMEWHERE", "a", "b"))
	assert.Equal(t, "", under(cfg, "NOT_SET", "a"),
		"a missing base must not produce a relative path")
}
