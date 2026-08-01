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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestParseDaemonCoreArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want DaemonCoreArgs
	}{
		{
			name: "the command line condor_master actually builds",
			args: []string{"/usr/sbin/pelican-server", "PELICAN", "-f", "-local-name", "cache_a"},
			want: DaemonCoreArgs{LocalName: "cache_a"},
		},
		{
			name: "two dashes are equivalent to one",
			args: []string{"pelican-server", "--local-name", "cache_b"},
			want: DaemonCoreArgs{LocalName: "cache_b"},
		},
		{
			name: "shared-port endpoint",
			args: []string{"pelican-server", "-local-name", "c", "-sock", "pelican_c"},
			want: DaemonCoreArgs{LocalName: "c", Sock: "pelican_c"},
		},
		{
			name: "nothing to take",
			args: []string{"pelican-server"},
			want: DaemonCoreArgs{},
		},
		{
			// A flag whose value is missing must not consume the loop or panic.
			name: "trailing flag without a value",
			args: []string{"pelican-server", "-local-name"},
			want: DaemonCoreArgs{},
		},
		{
			// Unrecognized arguments are skipped rather than rejected: the master
			// passes version-dependent flags, and refusing them would mean a pool
			// that will not start after an HTCondor upgrade.
			name: "unknown flags are ignored",
			args: []string{"pelican-server", "-t", "-p", "0", "-unheard-of", "x", "-local-name", "d"},
			want: DaemonCoreArgs{LocalName: "d"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseDaemonCoreArgs(tc.args))
		})
	}
}

// TestLocalNameScopesConfigLookups is the reason the parser exists. Two
// instances of the daemon on one host are distinguished only by their local
// name, and a daemon that dropped it would read the shared value and appear to
// work while being misconfigured.
func TestLocalNameScopesConfigLookups(t *testing.T) {
	const text = `
PELICAN_PORT = 8444
CACHE_A.PELICAN_PORT = 9444
PELICAN.CACHE_B.PELICAN_PORT = 9555
lower_c.PELICAN_PORT = 9555
`
	withLocalName := func(name string) *config.Config {
		cfg, err := config.NewFromReaderWithOptions(strings.NewReader(text), config.ConfigOptions{
			Subsystem: Subsys, LocalName: name,
		})
		require.NoError(t, err)
		return cfg
	}

	assert.Equal(t, "8444", knobString(withLocalName(""), "PELICAN_PORT"),
		"with no local name the bare knob applies")
	assert.Equal(t, "9444", knobString(withLocalName("CACHE_A"), "PELICAN_PORT"),
		"<LOCALNAME>.<KEY> should override the bare knob")
	assert.Equal(t, "9555", knobString(withLocalName("CACHE_B"), "PELICAN_PORT"),
		"<SUBSYS>.<LOCALNAME>.<KEY> should override the bare knob")

	// Case does not matter in either direction, so the parser passes the name
	// through as written rather than normalizing it.
	assert.Equal(t, "9444", knobString(withLocalName("cache_a"), "PELICAN_PORT"),
		"a lower-case local name should find an upper-case definition")
	assert.Equal(t, "9555", knobString(withLocalName("LOWER_C"), "PELICAN_PORT"),
		"an upper-case local name should find a lower-case definition")
}
