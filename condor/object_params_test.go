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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEveryObjectParamIsHandled is the runtime half of the completeness
// guarantee. The generated constructor already makes a missing handler a
// compile error; this checks the other direction -- that the registry has not
// drifted to cover a parameter that no longer exists -- and that every handler
// is either a real translation or an explicit, explained refusal.
func TestEveryObjectParamIsHandled(t *testing.T) {
	require.NotEmpty(t, ObjectParamNames, "generated object-parameter list is empty")

	for _, name := range ObjectParamNames {
		h, ok := objectParams.Handler(name)
		require.True(t, ok, "no handler registered for object parameter %s", name)
		assert.Equal(t, name, h.Param, "handler registered under the wrong name")

		if h.Supported() {
			assert.NotNil(t, h.Decode, "%s is supported but has no Decode function", name)
		} else {
			assert.NotEmpty(t, h.UnsupportedReason(),
				"%s is unsupported but gives no reason; an operator who sets it deserves to be told why", name)
			assert.Nil(t, h.Decode, "%s is unsupported but has a Decode function", name)
		}
	}

	assert.Len(t, objectParams.handlers, len(ObjectParamNames),
		"the registry covers a different number of parameters than parameters.yaml declares")
}

// TestGeneratedListMatchesParametersYaml guards against the generated file being
// stale -- a developer who adds an object parameter but does not regenerate
// would otherwise get no signal from this package at all, since the compile-time
// check depends on the generated file being current.
func TestGeneratedListMatchesParametersYaml(t *testing.T) {
	path, err := filepath.Abs("../docs/parameters.yaml")
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	// Count "type: object" declarations without a YAML dependency: the file is a
	// stream of documents, one parameter each.
	want := 0
	for _, line := range splitLines(string(raw)) {
		if line == "type: object" {
			want++
		}
	}
	assert.Equal(t, want, len(ObjectParamNames),
		"condor/object_params_gen.go is stale; run \"make generate\"")
}

func splitLines(s string) []string {
	lines := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, trimCR(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, trimCR(s[start:]))
	}
	return lines
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}

func TestOriginExportsKnobFamily(t *testing.T) {
	h, ok := objectParams.Handler("Origin.Exports")
	require.True(t, ok)
	require.True(t, h.Supported())

	t.Run("decodes a two-item family", func(t *testing.T) {
		cfg := configFrom(t, `
PELICAN_ORIGIN_EXPORTS = public, protected
PELICAN_ORIGIN_EXPORT_PUBLIC_FEDERATIONPREFIX = /ospool/public
PELICAN_ORIGIN_EXPORT_PUBLIC_STORAGEPREFIX = /data/public
PELICAN_ORIGIN_EXPORT_PUBLIC_CAPABILITIES = PublicReads, Reads
PELICAN_ORIGIN_EXPORT_PROTECTED_FEDERATIONPREFIX = /ospool/protected
PELICAN_ORIGIN_EXPORT_PROTECTED_STORAGEPREFIX = /data/protected
PELICAN_ORIGIN_EXPORT_PROTECTED_CAPABILITIES = Reads Writes
`)
		got, err := h.Decode(cfg)
		require.NoError(t, err)
		exports, ok := got.([]originExport)
		require.True(t, ok, "expected []originExport, got %T", got)
		require.Len(t, exports, 2)

		assert.Equal(t, "/ospool/public", exports[0].FederationPrefix)
		assert.Equal(t, "/data/public", exports[0].StoragePrefix)
		assert.Equal(t, []string{"PublicReads", "Reads"}, exports[0].Capabilities)

		assert.Equal(t, "/ospool/protected", exports[1].FederationPrefix)
		// Whitespace separation works as well as commas, matching how HTCondor's
		// own list-valued knobs are written.
		assert.Equal(t, []string{"Reads", "Writes"}, exports[1].Capabilities)
	})

	t.Run("no list knob yields no value", func(t *testing.T) {
		got, err := h.Decode(configFrom(t, "# nothing here\n"))
		require.NoError(t, err)
		assert.Nil(t, got, "an unconfigured parameter must not fabricate an empty list")
	})

	t.Run("an item missing a required field is an error", func(t *testing.T) {
		cfg := configFrom(t, `
PELICAN_ORIGIN_EXPORTS = public
PELICAN_ORIGIN_EXPORT_PUBLIC_STORAGEPREFIX = /data/public
`)
		_, err := h.Decode(cfg)
		require.Error(t, err, "a half-specified export must fail loudly, not be silently dropped")
		assert.Contains(t, err.Error(), "FEDERATIONPREFIX")
	})

	t.Run("an item named in the list but not defined is an error", func(t *testing.T) {
		cfg := configFrom(t, "PELICAN_ORIGIN_EXPORTS = ghost\n")
		_, err := h.Decode(cfg)
		require.Error(t, err, "the list knob is authoritative; a named item must exist")
	})
}

func TestKnobList(t *testing.T) {
	cfg := configFrom(t, `
COMMAS = a, b ,c
SPACES = a b  c
MIXED = a, b c
TRAILING = a, b,
EMPTY =
`)
	for _, tc := range []struct{ knob string }{{"COMMAS"}, {"SPACES"}, {"MIXED"}} {
		assert.Equal(t, []string{"a", "b", "c"}, knobList(cfg, tc.knob), tc.knob)
	}
	assert.Equal(t, []string{"a", "b"}, knobList(cfg, "TRAILING"),
		"a trailing separator should not produce an empty item")
	assert.Nil(t, knobList(cfg, "EMPTY"))
	assert.Nil(t, knobList(cfg, "NOT_SET"))
}

func TestKnobToken(t *testing.T) {
	assert.Equal(t, "PUBLIC", knobToken("public"))
	assert.Equal(t, "MY_EXPORT", knobToken("my-export"))
	assert.Equal(t, "MY_EXPORT", knobToken(" my_export "))
	assert.Equal(t, "A1_B2", knobToken("a1.b2"))
}

// configFrom builds an HTCondor configuration from literal text.
func configFrom(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(text))
	require.NoError(t, err)
	return cfg
}
