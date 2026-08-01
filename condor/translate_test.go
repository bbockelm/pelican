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
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestParamKnob(t *testing.T) {
	assert.Equal(t, "PELICAN_CACHE_ENABLEV2", ParamKnob("Cache.EnableV2"))
	assert.Equal(t, "PELICAN_ORIGIN_EXPORTS", ParamKnob("Origin.Exports"))
	assert.Equal(t, "PELICAN_TLSSKIPVERIFY", ParamKnob("TLSSkipVerify"))

	// The knob spelling must stay identical to the parameter's environment
	// variable; if they diverge, operators and the docs are both wrong.
	assert.Equal(t, param.Cache_EnableV2.GetEnvVarName(), ParamKnob(param.Cache_EnableV2.GetName()))
	assert.Equal(t, param.Server_WebPort.GetEnvVarName(), ParamKnob(param.Server_WebPort.GetName()))
}

// TestApplyCondorConfigTypes checks that string knob values become correctly
// typed Pelican parameters. No per-parameter type table is involved: viper's
// decode hooks do the conversion, the same way they do for environment
// variables. This is the assumption that makes the translation table-free, so it
// is worth pinning down.
func TestApplyCondorConfigTypes(t *testing.T) {
	v := viper.New()
	cfg := configFrom(t, `
PELICAN_TLSSKIPVERIFY = true
PELICAN_SERVER_WEBPORT = 8444
PELICAN_LOGGING_LEVEL = debug
PELICAN_SERVER_STARTUPTIMEOUT = 45s
PELICAN_DIRECTOR_CACHESORTMETHOD = adaptive
`)
	require.NoError(t, applyCondorConfig(v, cfg))

	assert.True(t, v.GetBool("Server.EnableUI") == false, "unset parameters must stay untouched")
	assert.True(t, v.GetBool("TLSSkipVerify"), "bool knob")
	assert.Equal(t, 8444, v.GetInt("Server.WebPort"), "int knob")
	assert.Equal(t, "debug", v.GetString("Logging.Level"), "string knob")
	assert.Equal(t, 45*time.Second, v.GetDuration("Server.StartupTimeout"), "duration knob")
	assert.Equal(t, "adaptive", v.GetString("Director.CacheSortMethod"))
}

func TestApplyCondorConfigObjectParam(t *testing.T) {
	v := viper.New()
	cfg := configFrom(t, `
PELICAN_ORIGIN_EXPORTS = public
PELICAN_ORIGIN_EXPORT_PUBLIC_FEDERATIONPREFIX = /ospool/public
PELICAN_ORIGIN_EXPORT_PUBLIC_STORAGEPREFIX = /data/public
PELICAN_ORIGIN_EXPORT_PUBLIC_CAPABILITIES = Reads
`)
	require.NoError(t, applyCondorConfig(v, cfg))

	var exports []originExport
	require.NoError(t, v.UnmarshalKey("Origin.Exports", &exports))
	require.Len(t, exports, 1)
	assert.Equal(t, "/ospool/public", exports[0].FederationPrefix)
	assert.Equal(t, "/data/public", exports[0].StoragePrefix)
}

func TestApplyCondorConfigIgnoresBlankAndUnset(t *testing.T) {
	v := viper.New()
	v.Set("Logging.Level", "info")

	// A knob present but blank means "unset". Merging an empty string would
	// replace a working value with nothing, which is worse than ignoring it.
	cfg := configFrom(t, "PELICAN_LOGGING_LEVEL =\n")
	require.NoError(t, applyCondorConfig(v, cfg))
	assert.Equal(t, "info", v.GetString("Logging.Level"))
}

func TestApplyCondorConfigRejectsBadObjectParam(t *testing.T) {
	v := viper.New()
	cfg := configFrom(t, "PELICAN_ORIGIN_EXPORTS = broken\n")
	err := applyCondorConfig(v, cfg)
	require.Error(t, err, "an unusable knob family must fail startup, not be skipped")
	assert.Contains(t, err.Error(), "Origin.Exports")
}

func TestNest(t *testing.T) {
	got := nest(map[string]any{
		"Server.WebPort":   "8444",
		"Server.EnableUI":  "false",
		"TLSSkipVerify":    "true",
		"Origin.Exports":   []originExport{{FederationPrefix: "/a"}},
		"Director.DbLoc.X": "y",
	})

	// Lower-cased and nested, matching the shape viper's config layer holds.
	server, ok := got["server"].(map[string]any)
	require.True(t, ok, "Server.* should nest under a lower-cased \"server\" key")
	assert.Equal(t, "8444", server["webport"])
	assert.Equal(t, "false", server["enableui"])
	assert.Equal(t, "true", got["tlsskipverify"])

	director, ok := got["director"].(map[string]any)
	require.True(t, ok)
	dbloc, ok := director["dbloc"].(map[string]any)
	require.True(t, ok, "three-level keys should nest all the way down")
	assert.Equal(t, "y", dbloc["x"])
}

func TestValidateNativeBackends(t *testing.T) {
	origin := server_structs.NewServerType()
	origin.Set(server_structs.OriginType)
	cache := server_structs.NewServerType()
	cache.Set(server_structs.CacheType)
	director := server_structs.NewServerType()
	director.Set(server_structs.DirectorType)

	t.Run("an XRootD-backed origin is refused", func(t *testing.T) {
		v := viper.New()
		v.Set("Origin.StorageType", "posix")
		err := validateNativeBackends(v, origin)
		require.Error(t, err, "posix is XRootD-backed and must not start under condor_master")
		// The message has to name a way forward, or it is just a wall.
		assert.Contains(t, err.Error(), "posixv2")
	})

	t.Run("a native origin is accepted", func(t *testing.T) {
		for _, storage := range []string{"posixv2", "s3v2", "httpsv2", "globusv2", "ssh"} {
			v := viper.New()
			v.Set("Origin.StorageType", storage)
			assert.NoError(t, validateNativeBackends(v, origin), storage)
		}
	})

	t.Run("the XRootD cache is refused", func(t *testing.T) {
		v := viper.New()
		v.Set("Cache.EnableV2", false)
		err := validateNativeBackends(v, cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Cache.EnableV2")
	})

	t.Run("the native cache is accepted", func(t *testing.T) {
		v := viper.New()
		v.Set("Cache.EnableV2", true)
		assert.NoError(t, validateNativeBackends(v, cache))
	})

	t.Run("modules that never used XRootD are unaffected", func(t *testing.T) {
		// A director has no storage type at all; checking one would reject a
		// perfectly good configuration for a setting it does not use.
		assert.NoError(t, validateNativeBackends(viper.New(), director))
	})
}

// TestReapplyAppliesRuntimeConfigurableOnly is what makes condor_reconfig
// honest. A parameter Pelican allows to change at runtime is applied through
// its own hot-reload path; one that is bound at startup is reported instead, so
// an operator is never left believing a reconfigure took effect when it did not.
func TestReapplyAppliesRuntimeConfigurableOnly(t *testing.T) {
	require.True(t, param.IsRuntimeConfigurable("Logging.Level"),
		"this test assumes Logging.Level is reloadable")
	require.False(t, param.IsRuntimeConfigurable("Server.WebPort"),
		"this test assumes Server.WebPort is not reloadable")

	require.NoError(t, param.Logging_Level.Set("info"))
	require.NoError(t, param.Server_WebPort.Set(8444))

	cfg := configFrom(t, `
PELICAN_LOGGING_LEVEL = debug
PELICAN_SERVER_WEBPORT = 9999
`)
	applied, deferred, err := Reapply(cfg)
	require.NoError(t, err)

	assert.Contains(t, applied, "Logging.Level", "a reloadable parameter should be applied")
	assert.Equal(t, "debug", param.Logging_Level.GetString(), "and should actually take effect")

	assert.Contains(t, deferred, "Server.WebPort", "a startup-bound parameter should be reported")
	assert.Equal(t, 8444, param.Server_WebPort.GetInt(), "and must not be half-applied")
}

func TestReapplyIgnoresUnchanged(t *testing.T) {
	require.NoError(t, param.Logging_Level.Set("warn"))
	applied, deferred, err := Reapply(configFrom(t, "PELICAN_LOGGING_LEVEL = warn\n"))
	require.NoError(t, err)
	assert.Empty(t, applied, "an unchanged value is not a change")
	assert.Empty(t, deferred)
}

// TestReapplyNotifiesCallbacks checks the hook actually reaches Pelican's
// reload mechanism rather than only writing to viper. Modules react through
// param.RegisterCallback, so a reconfigure that skipped it would update the
// value while leaving the subsystem using it none the wiser.
func TestReapplyNotifiesCallbacks(t *testing.T) {
	require.NoError(t, param.Logging_Level.Set("info"))

	notified := make(chan string, 4)
	param.RegisterCallback("condor-reapply-test", func(_, newConfig *param.Config) {
		notified <- newConfig.Logging.Level
	})
	t.Cleanup(param.ClearCallbacks)

	_, _, err := Reapply(configFrom(t, "PELICAN_LOGGING_LEVEL = error\n"))
	require.NoError(t, err)

	select {
	case level := <-notified:
		assert.Equal(t, "error", level, "the callback should see the new value")
	case <-time.After(10 * time.Second):
		t.Fatal("no module was notified of the configuration change")
	}
}
