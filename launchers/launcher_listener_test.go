//go:build server && !windows

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

package launchers_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestLaunchModulesWithListener checks that a caller-supplied listener is the one
// the web engine actually serves on, and that the configuration derived from the
// listener's address (Server.WebPort and the URLs built from it) is resolved from
// the injected socket rather than from a second bind.
//
// Director + registry is used because it is the lightest module set that stands
// up the web engine and needs no XRootD process. The director is required so the
// federation has a discovery source; a registry on its own refuses to start
// without one.
func TestLaunchModulesWithListener(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	tmpPath := t.TempDir()
	require.NoError(t, param.ConfigBase.Set(tmpPath))
	require.NoError(t, param.RuntimeDir.Set(tmpPath))
	require.NoError(t, param.Logging_Level.Set("Debug"))
	require.NoError(t, param.TLSSkipVerify.Set(true))
	require.NoError(t, param.Server_EnableUI.Set(false))
	require.NoError(t, param.Server_DbLocation.Set(filepath.Join(tmpPath, "ns-registry.sqlite")))
	require.NoError(t, param.Director_DbLocation.Set(filepath.Join(tmpPath, "director.sqlite")))
	require.NoError(t, param.Registry_RequireOriginApproval.Set(false))
	require.NoError(t, param.Registry_RequireCacheApproval.Set(false))
	// The director is this federation's discovery source.
	require.NoError(t, param.Director_EnableFederationMetadataHosting.Set(true))

	// Bind the listener ourselves, the way an embedder would. Port 0 exercises the
	// path where the configuration must be resolved from the listener's address --
	// if LaunchModules were to bind its own socket instead, it would land on a
	// different port and the assertions below would catch it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	injectedPort := ln.Addr().(*net.TCPAddr).Port
	require.NotZero(t, injectedPort)

	// Server.WebPort is deliberately left at 0 so that any value it ends up with
	// must have come from the injected listener.
	require.NoError(t, param.Server_WebPort.Set(0))

	modules := server_structs.ServerType(0)
	modules.Set(server_structs.DirectorType)
	modules.Set(server_structs.RegistryType)

	_, shutdownCancel, err := launchers.LaunchModules(ctx, modules, launchers.WithListener(ln))
	require.NoError(t, err)
	defer shutdownCancel()

	// The configuration was resolved from our socket, not from a bind of its own.
	assert.Equal(t, injectedPort, param.Server_WebPort.GetInt(),
		"Server.WebPort should be resolved from the injected listener")
	assert.Contains(t, param.Server_ExternalWebUrl.GetString(), strconv.Itoa(injectedPort),
		"Server.ExternalWebUrl should carry the injected listener's port")

	// The engine is serving on the injected socket specifically -- addressed by the
	// port we bound, not by whatever the configuration happens to say.
	healthUrl := "https://" + net.JoinHostPort("localhost", strconv.Itoa(injectedPort)) + "/api/v1.0/health"
	require.NoError(t, server_utils.WaitUntilWorking(ctx, "GET", healthUrl, "registry", http.StatusOK, false))

	httpc := http.Client{Transport: config.GetTransport()}
	resp, err := httpc.Get(healthUrl)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
