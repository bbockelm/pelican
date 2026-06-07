//go:build client && !windows

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

package main

// This file contains an end-to-end integration test for the native HTCondor
// credmon ⇄ Pelican integration.  It exercises:
//
//   - the merged condor_vault_storer (a SEC_CREDENTIAL_STORER) detecting a
//     Pelican service and running the Pelican client's OAuth2 device-code flow
//     at submit time,
//   - the PelicanCredmon performing an RFC 8693 token exchange using the
//     credmon's own client credentials,
//   - a job that uses transfer_input_files = pelican://… (the Pelican file
//     transfer plugin / URL integration) with the exchanged token, and
//   - the credmon's periodic refresh flow (triggered via SIGHUP).
//
// The credmon (condor_credmon_oauth + its PelicanCredmon) and the merged
// condor_vault_storer are taken from the installed HTCondor; the test skips
// unless they implement the Pelican integration.  Their locations can be
// overridden with the PELICAN_CONDOR_CREDMON, PELICAN_CONDOR_CREDENTIAL_STORER,
// and PELICAN_CONDOR_CREDMON_LIBEXEC environment variables.
//
// Like the other HTCondor integration tests, this is gated behind the
// `client` build tag and skips when condor_master is unavailable.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// The OAuth service name registered with HTCondor.
const credmonServiceName = "pelicantest"

// credmonOriginConfig enables the embedded OIDC issuer on a POSIXv2 origin with
// a single export, /credmon-test, that any authenticated user may read/write.
//
// NOTE: the AuthorizationTemplate prefix is "/" — namespace-relative, NOT the
// absolute federation path /credmon-test.  The Pelican client requests scopes
// relative to the namespace (e.g. storage.read:/) and XRootD validates with
// base_path=/credmon-test, so the issued scope paths must also be
// namespace-relative for both the client and XRootD to accept the token.
const credmonOriginConfig = `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /credmon-test
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
Issuer:
  AuthorizationTemplates:
    - prefix: /
      actions: ["read", "write", "create"]
`

// resolveCredmonScript returns the path to a credmon helper script.  Resolution
// tries, in order:
//
//  1. an explicit environment-variable override (PELICAN_CONDOR_CREDMON /
//     PELICAN_CONDOR_CREDENTIAL_STORER), and
//  2. a system install (so the test runs automatically wherever the credmon is
//     installed, including once the support lands upstream).
//
// Whichever is chosen is then capability-checked by detectPelicanSupport; if it
// predates the Pelican support the whole test is skipped rather than failing.
// Returns "" if nothing is found (the caller skips).
func resolveCredmonScript(t *testing.T, envVar string, systemFallback func() string) string {
	if override := os.Getenv(envVar); override != "" {
		if _, err := os.Stat(override); err != nil {
			t.Skipf("%s=%s but the file is not accessible: %v", envVar, override, err)
		}
		return override
	}
	if systemFallback != nil {
		if p := systemFallback(); p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// condorConfigVal returns the value of an HTCondor config knob, or "" on error.
func condorConfigVal(knob string) string {
	out, err := exec.Command("condor_config_val", knob).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// locateCredmonPackageDir finds the directory that contains the `credmon`
// Python package for the given daemon.  It normally lives in HTCondor's LIBEXEC
// (or next to the daemon).  An explicit override is honored via
// PELICAN_CONDOR_CREDMON_LIBEXEC.
func locateCredmonPackageDir(daemonPath string) string {
	candidates := []string{}
	if env := os.Getenv("PELICAN_CONDOR_CREDMON_LIBEXEC"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, filepath.Dir(daemonPath))
	if libexec := condorConfigVal("LIBEXEC"); libexec != "" {
		candidates = append(candidates, libexec)
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "credmon", "CredentialMonitors")); err == nil {
			return dir
		}
	}
	return ""
}

// detectPelicanSupport reports whether the resolved credmon package and storer
// actually implement the Pelican integration.  It returns a human-readable
// reason when support is missing so the caller can skip with a clear message.
func detectPelicanSupport(credmonPkgDir, storerScript string) (ok bool, reason string) {
	if credmonPkgDir == "" {
		return false, "could not locate the credmon Python package (set PELICAN_CONDOR_CREDMON or PELICAN_CONDOR_CREDMON_LIBEXEC)"
	}
	// The credmon must ship the PelicanCredmon monitor.
	pelicanCredmon := filepath.Join(credmonPkgDir, "credmon", "CredentialMonitors", "PelicanCredmon.py")
	if _, err := os.Stat(pelicanCredmon); err != nil {
		return false, fmt.Sprintf("credmon at %s lacks PelicanCredmon.py (Pelican credmon support is not yet present)", credmonPkgDir)
	}
	// The storer must understand Pelican services.  The merged condor_vault_storer
	// keys off the PELICAN_CREDMON_PROVIDER_NAMES knob.
	storerData, err := os.ReadFile(storerScript)
	if err != nil {
		return false, fmt.Sprintf("could not read storer %s: %v", storerScript, err)
	}
	if !bytes.Contains(storerData, []byte("PELICAN_CREDMON_PROVIDER_NAMES")) {
		return false, fmt.Sprintf("storer %s does not understand Pelican services (no PELICAN_CREDMON_PROVIDER_NAMES handling)", storerScript)
	}
	return true, ""
}

// TestHTCondorPelicanCredmon proves the full submit → device-flow → token
// exchange → job → refresh pipeline between HTCondor and a Pelican federation.
func TestHTCondorPelicanCredmon(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}
	if _, err := exec.LookPath("condor_store_cred"); err != nil {
		t.Skip("condor_store_cred not found in PATH, skipping integration test")
	}

	// Locate the credmon daemon, its Python package, and the storer.  These are
	// taken from the installed HTCondor (overridable via env).
	credmonDaemon := resolveCredmonScript(t, "PELICAN_CONDOR_CREDMON",
		func() string {
			if v := condorConfigVal("CREDMON_OAUTH"); v != "" {
				return v
			}
			return "/usr/sbin/condor_credmon_oauth"
		})
	// The storer is the merged condor_vault_storer, which routes each service to
	// the Vault or Pelican credmon based on PELICAN_CREDMON_PROVIDER_NAMES.
	storerScript := resolveCredmonScript(t, "PELICAN_CONDOR_CREDENTIAL_STORER",
		func() string {
			if p, err := exec.LookPath("condor_vault_storer"); err == nil {
				return p
			}
			return ""
		})
	if credmonDaemon == "" || storerScript == "" {
		t.Skip("Pelican credmon daemon and/or storer not found; set PELICAN_CONDOR_CREDMON and " +
			"PELICAN_CONDOR_CREDENTIAL_STORER to a build that includes the Pelican credmon support")
	}

	// Verify the resolved credmon + storer actually implement the Pelican
	// integration (it is not yet upstream).  Skip cleanly if not, rather than
	// failing against a stock HTCondor.
	credmonPkgDir := locateCredmonPackageDir(credmonDaemon)
	if ok, reason := detectPelicanSupport(credmonPkgDir, storerScript); !ok {
		t.Skipf("HTCondor does not support the Pelican credmon yet: %s. "+
			"Point PELICAN_CONDOR_CREDMON / PELICAN_CONDOR_CREDENTIAL_STORER at a supporting build.", reason)
	}

	// Determine the user that runs the daemons (root/condor) and the user that
	// submits jobs (cannot be root).
	var condorUsername, jobUsername string
	if os.Geteuid() == 0 {
		condorUsername = "condor"
		jobUsername = "alice"
	} else {
		cur, err := user.Current()
		require.NoError(t, err)
		condorUsername = cur.Username
		jobUsername = cur.Username
	}
	condorUser, err := user.Lookup(condorUsername)
	if err != nil {
		t.Skipf("Required user %q not found: %v", condorUsername, err)
	}
	condorUid, _ := strconv.Atoi(condorUser.Uid)
	condorGid, _ := strconv.Atoi(condorUser.Gid)
	jobUser, err := user.Lookup(jobUsername)
	if err != nil {
		t.Skipf("Required user %q not found: %v", jobUsername, err)
	}
	jobUid, _ := strconv.Atoi(jobUser.Uid)
	jobGid, _ := strconv.Atoi(jobUser.Gid)

	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	// ----- Step 0: htpasswd with an admin and a "testuser" approver -----
	htpasswdDir := t.TempDir()
	require.NoError(t, os.Chmod(htpasswdDir, 0755))
	htpasswdFile := filepath.Join(htpasswdDir, "htpasswd")
	adminPassword := credmonRandomString(16)
	testUserPassword := credmonRandomString(16)
	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	testUserHash, err := bcrypt.GenerateFromPassword([]byte(testUserPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(htpasswdFile,
		[]byte(fmt.Sprintf("admin:%s\ntestuser:%s\n", string(adminHash), string(testUserHash))), 0644))
	require.NoError(t, param.Server_UIPasswordFile.Set(htpasswdFile))

	// ----- Step 1: start the federation with the embedded issuer -----
	tempDir, err := os.MkdirTemp("", "htc-credmon-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempDir) })
	require.NoError(t, os.Chmod(tempDir, 0711))

	exportDir := filepath.Join(tempDir, "credmon-store")
	require.NoError(t, os.MkdirAll(exportDir, 0755))

	ft := fed_test_utils.NewFedTest(t, fmt.Sprintf(credmonOriginConfig, exportDir))
	require.NotNil(t, ft)

	serverURL := param.Server_ExternalWebUrl.GetString()
	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	nsBase := serverURL + "/api/v1.0/issuer/ns/credmon-test"
	t.Logf("Federation up at %s (issuer ns base %s)", serverURL, nsBase)

	// Pre-create the file the job will download from the federation.  Use the
	// *actual* StoragePrefix from the export, which NewFedTest may have rewritten
	// from the value we passed in the config.
	require.GreaterOrEqual(t, len(ft.Exports), 1, "federation should have an export")
	backendDir := ft.Exports[0].StoragePrefix
	const downloadContent = "credmon integration test payload\n"
	require.NoError(t, os.WriteFile(filepath.Join(backendDir, "payload.txt"), []byte(downloadContent), 0644))

	// HTTP client that trusts the federation CA and remembers cookies.
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// ----- Step 2: create the credmon's OAuth2 client via the admin API -----
	// Unlike public DCR (device_code + refresh_token only), the admin API can
	// grant the token-exchange grant the credmon needs.
	credmonClientID, credmonClientSecret := createCredmonClient(t, httpClient, serverURL, "admin", adminPassword)
	t.Logf("Created credmon client %s via admin API", credmonClientID)

	clientSecretFile := filepath.Join(tempDir, "credmon_client_secret")
	require.NoError(t, os.WriteFile(clientSecretFile, []byte(credmonClientSecret), 0640))
	require.NoError(t, os.Chown(clientSecretFile, condorUid, condorGid))

	// ----- Step 3: build the pelican binary, copy it & the storer somewhere
	// the submitting user can execute -----
	pelicanBinary := getPelicanBinary(t)
	shareDir, err := os.MkdirTemp("/tmp", "pelican-credmon-share-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(shareDir) })
	require.NoError(t, os.Chmod(shareDir, 0755))

	pelicanShared := filepath.Join(shareDir, "pelican")
	copyExecutable(t, pelicanBinary, pelicanShared)
	storerShared := filepath.Join(shareDir, "condor_vault_storer")
	copyExecutable(t, storerScript, storerShared)

	// ----- Step 4: write the mini-condor config (credd + credmon enabled) -----
	credDir := filepath.Join(tempDir, "oauth_credentials")
	require.NoError(t, os.MkdirAll(credDir, 0770))
	require.NoError(t, os.Chown(credDir, condorUid, condorGid))
	logDir := filepath.Join(tempDir, "log")
	require.NoError(t, config.MkdirAll(logDir, 0755, condorUid, condorGid))
	socketDir, err := os.MkdirTemp("/tmp", "htc_credmon_sock_*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(socketDir) })

	pluginDir, err := os.MkdirTemp("/tmp", "pelican-credmon-libexec-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(pluginDir) })
	require.NoError(t, os.Chmod(pluginDir, 0755))
	pluginPath := filepath.Join(pluginDir, "pelican_plugin")
	copyExecutable(t, pelicanBinary, pluginPath)

	configFile := filepath.Join(tempDir, "condor_config")
	require.NoError(t, writeCredmonCondorConfig(credmonCondorConfigOpts{
		configFile:       configFile,
		tempDir:          tempDir,
		logDir:           logDir,
		socketDir:        socketDir,
		pluginPath:       pluginPath,
		credDir:          credDir,
		credmonDaemon:    credmonDaemon,
		credmonPkgDir:    credmonPkgDir,
		storer:           storerShared,
		service:          credmonServiceName,
		federationURL:    serverURL,
		prefix:           "/credmon-test",
		clientID:         credmonClientID,
		clientSecretFile: clientSecretFile,
	}))

	t.Setenv("CONDOR_CONFIG", configFile)

	// ----- Step 5: start condor_master (with PYTHONPATH for the credmon) -----
	ctx, cancel := context.WithCancel(ft.Ctx)
	defer cancel()
	condorMaster := exec.CommandContext(ctx, "condor_master", "-f")
	condorMaster.Env = append(os.Environ(),
		"CONDOR_CONFIG="+configFile,
		"PYTHONPATH="+credmonPkgDir,
	)
	condorMaster.Stdout = os.Stdout
	condorMaster.Stderr = os.Stderr
	require.NoError(t, condorMaster.Start())
	defer stopCondorMaster(condorMaster, t)

	require.NoError(t, waitForCondor(tempDir, 60*time.Second, t))
	t.Log("HTCondor (with credd + credmon) is ready")

	// ----- Step 6: write the job and submit it -----
	jobDir := filepath.Join(tempDir, "job")
	require.NoError(t, config.MkdirAll(jobDir, 0755, jobUid, jobGid))

	scriptPath := filepath.Join(jobDir, "job.sh")
	// The job prints its delivered token (so the test can inspect the exchanged
	// token) and the downloaded payload.
	scriptContent := `#!/bin/bash
echo "=== CREDMON TOKEN BEGIN ==="
cat "$_CONDOR_CREDS/` + credmonServiceName + `.use"
echo ""
echo "=== CREDMON TOKEN END ==="
echo "=== PAYLOAD BEGIN ==="
cat payload.txt || echo "FAILED to read payload.txt"
echo "=== PAYLOAD END ==="
`
	require.NoError(t, os.WriteFile(scriptPath, []byte(scriptContent), 0755))

	federationURL := fmt.Sprintf("pelican://%s:%d", hostname, port)
	submitFile := filepath.Join(jobDir, "job.sub")
	submitContent := fmt.Sprintf(`executable = %s
log = %s/job.log
output = %s/job.out
error = %s/job.err

use_oauth_services = %s
transfer_input_files = %s/credmon-test/payload.txt

should_transfer_files = YES
when_to_transfer_output = ON_EXIT

+PelicanCfg_TLSSkipVerify = true

queue
`, scriptPath, jobDir, jobDir, jobDir, credmonServiceName, federationURL)
	require.NoError(t, os.WriteFile(submitFile, []byte(submitContent), 0644))

	// Environment for condor_submit (and thus the storer subprocess).
	submitEnv := append(os.Environ(),
		"CONDOR_CONFIG="+configFile,
		"PELICAN_BIN="+pelicanShared,
		"PELICAN_SKIP_TERMINAL_CHECK=1",
		"PELICAN_TLSSKIPVERIFY=true",
		"PELICAN_FEDERATION_DISCOVERYURL="+serverURL,
		"HOME="+jobUser.HomeDir,
	)

	clusterID := submitWithDeviceApproval(ctx, t, submitFile, submitEnv, jobUid, jobGid,
		httpClient, serverURL, "testuser", testUserPassword)
	require.NotEmpty(t, clusterID, "Failed to submit credmon job")
	t.Logf("Job submitted (cluster %s)", clusterID)

	topPath := filepath.Join(credDir, jobUsername, credmonServiceName+".top")
	usePath := filepath.Join(credDir, jobUsername, credmonServiceName+".use")

	// Capture the storer's subject token (still in .top) before the credmon
	// exchanges it, so we can later prove the exchange minted a *different*
	// token by comparing JTIs.  Best-effort: if the credmon's periodic scan
	// already exchanged it, the subject token is gone and we skip that check.
	subjectJTI := ""
	if raw, e := os.ReadFile(topPath); e == nil {
		var top map[string]interface{}
		if json.Unmarshal(raw, &top) == nil {
			if at, ok := top["access_token"].(string); ok && at != "" {
				subjectJTI = jtiOf(t, at)
			}
		}
	}

	// Kick the credmon so the token exchange happens promptly rather than on the
	// next 60s scan.
	sighupCredmon(t, credDir)

	// ----- Step 7: wait for the job and verify the exchanged token -----
	require.NoError(t, waitForJobCompletion(tempDir, clusterID, 180*time.Second, t))

	outBytes, err := os.ReadFile(filepath.Join(jobDir, "job.out"))
	if errBytes, e := os.ReadFile(filepath.Join(jobDir, "job.err")); e == nil && len(errBytes) > 0 {
		t.Logf("Job stderr:\n%s", string(errBytes))
	}
	require.NoError(t, err, "job stdout should exist")
	jobOut := string(outBytes)
	t.Logf("Job stdout:\n%s", jobOut)

	assert.Contains(t, jobOut, downloadContent,
		"Job should have downloaded payload.txt from the federation using the exchanged token")

	jobToken := extractBetween(jobOut, "=== CREDMON TOKEN BEGIN ===", "=== CREDMON TOKEN END ===")
	jobToken = strings.TrimSpace(jobToken)
	require.NotEmpty(t, jobToken, "Job should have received a token in $_CONDOR_CREDS")
	// The delivered .use is JSON; pull out the access_token.
	jobAccessToken := accessTokenFromUse(t, jobToken)

	claims := decodeJWTClaims(t, jobAccessToken)
	assert.Equal(t, "testuser", claims["sub"], "exchanged token subject should be the approver")
	scopeStr := scopeString(claims)
	t.Logf("Exchanged token scopes: %s", scopeStr)
	// Scopes are namespace-relative (base_path=/credmon-test), so a token good
	// for the whole prefix carries storage.read:/.  The service is configured
	// for multiple permissions ("read, modify"), which do not imply one another,
	// so both capabilities must be present.
	assert.Contains(t, scopeStr, "storage.read:/",
		"exchanged token should retain the storage.read scope for the configured prefix")
	assert.Contains(t, scopeStr, "storage.modify:/",
		"exchanged token should carry storage.modify from the multi-valued PERMISSIONS")
	assert.Contains(t, scopeStr, "offline_access",
		"exchanged token should retain offline_access so the credmon can refresh")
	assert.Equal(t, claims["iss"], nsBaseIssuer(serverURL), "token issued by the credmon-test issuer")

	// Directly prove the exchange happened: the credmon replaces the storer's
	// subject token in .top with a refresh token.
	topData := readJSONFile(t, topPath)
	_, hasRefresh := topData["refresh_token"]
	assert.True(t, hasRefresh,
		"after the exchange the .top file should hold a refresh_token (got keys %v)",
		slices.Sorted(maps.Keys(topData)))
	assert.NotContains(t, topData, "access_token",
		"the storer's subject token should have been consumed by the exchange")

	// Prove the exchange minted a new token: the exchanged token's JTI differs
	// from the subject token's JTI.
	exchangedJTI := jtiFromClaims(claims)
	require.NotEmpty(t, exchangedJTI, "exchanged token should carry a jti claim")
	if subjectJTI != "" {
		assert.NotEqual(t, subjectJTI, exchangedJTI,
			"exchanged token jti should differ from the subject token jti")
		t.Logf("Exchange verified by JTI: subject=%s exchanged=%s", subjectJTI, exchangedJTI)
	} else {
		t.Log("Subject token jti was not captured (credmon raced ahead); relying on .top refresh_token for exchange proof")
	}

	// ----- Step 8: backdate the access token and verify refresh -----
	useBefore := readJSONFile(t, usePath)
	accessBefore, _ := useBefore["access_token"].(string)
	require.NotEmpty(t, accessBefore)

	// "Backdate" the access token by giving it a tiny remaining lifetime, then
	// signal the credmon to rescan.
	backdated := map[string]interface{}{
		"access_token": accessBefore,
		"token_type":   "Bearer",
		"expires_in":   1,
	}
	writeJSONFile(t, usePath, backdated)
	time.Sleep(2 * time.Second)
	sighupCredmon(t, credDir)

	require.Eventually(t, func() bool {
		cur := readJSONFileNoFail(usePath)
		curAccess, _ := cur["access_token"].(string)
		return curAccess != "" && curAccess != accessBefore
	}, 90*time.Second, 3*time.Second,
		"credmon should refresh the access token after SIGHUP")

	useAfter := readJSONFile(t, usePath)
	accessAfter, _ := useAfter["access_token"].(string)
	require.NotEqual(t, accessBefore, accessAfter, "refreshed access token should differ")
	refreshedClaims := decodeJWTClaims(t, accessAfter)
	assert.Equal(t, "testuser", refreshedClaims["sub"], "refreshed token subject preserved")
	refreshedScopes := scopeString(refreshedClaims)
	assert.Contains(t, refreshedScopes, "storage.read:/",
		"refreshed token should retain the storage.read scope")
	assert.Contains(t, refreshedScopes, "storage.modify:/",
		"refreshed token should retain the storage.modify scope")

	// Prove the refresh produced a new token by comparing JTIs.
	refreshedJTI := jtiFromClaims(refreshedClaims)
	require.NotEmpty(t, refreshedJTI, "refreshed token should carry a jti claim")
	assert.NotEqual(t, exchangedJTI, refreshedJTI,
		"refreshed token jti should differ from the exchanged token jti")
	t.Logf("Refresh verified by JTI: exchanged=%s refreshed=%s", exchangedJTI, refreshedJTI)

	t.Log("End-to-end credmon integration verified: device flow → token exchange → job → refresh")
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

type credmonCondorConfigOpts struct {
	configFile       string
	tempDir          string
	logDir           string
	socketDir        string
	pluginPath       string
	credDir          string
	credmonDaemon    string
	credmonPkgDir    string
	storer           string
	service          string
	federationURL    string
	prefix           string
	clientID         string
	clientSecretFile string
}

// writeCredmonCondorConfig writes a mini-condor configuration that runs the
// CREDD and CREDMON_OAUTH daemons and wires up the Pelican token service.
func writeCredmonCondorConfig(o credmonCondorConfigOpts) error {
	sbinDir, err := findHTCondorSbin()
	if err != nil {
		return err
	}
	binDir, err := findHTCondorBin()
	if err != nil {
		return err
	}
	libexecDir, err := findHTCondorLibexec()
	if err != nil {
		return err
	}

	svcUpper := strings.ToUpper(o.service)
	cfg := fmt.Sprintf(`# Mini HTCondor config for the Pelican credmon integration test
CONDOR_HOST = 127.0.0.1
LOCAL_DIR = %[1]s
LOG = %[2]s
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
LOCK = $(LOCAL_DIR)/lock
RUN = $(LOCAL_DIR)/run

SBIN = %[3]s
BIN = %[4]s
LIBEXEC = %[5]s
DAEMON_SOCKET_DIR = %[6]s

COLLECTOR_HOST = 127.0.0.1:0
BIND_ALL_INTERFACES = False
NETWORK_INTERFACE = 127.0.0.1
DAEMON_LIST = MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD, CREDD, CREDMON_OAUTH

COLLECTOR_ADDRESS_FILE = $(LOG)/.collector_address
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

ALLOW_WRITE = *
ALLOW_READ = *
ALLOW_ADMINISTRATOR = *

# Credential transfer to jobs requires encryption.
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, PASSWORD
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED

FILETRANSFER_PLUGINS = %[7]s

SCHEDD_INTERVAL = 5
NEGOTIATOR_INTERVAL = 5
NUM_CPUS = 1
MEMORY = 1024
START = True
SUSPEND = False
CONTINUE = True
PREEMPT = False
KILL = False
WANT_SUSPEND = False
WANT_VACATE = False

# ----- OAuth / credmon (equivalent of 'use feature : OAUTH') -----
CREDD_OAUTH_MODE = True
TRUST_CREDENTIAL_DIRECTORY = True
SEC_CREDENTIAL_DIRECTORY_OAUTH = %[8]s
CREDMON_OAUTH_LOG = $(LOG)/CredMonOAuthLog
SEC_CREDENTIAL_MONITOR_OAUTH_LOG = $(LOG)/CredMonOAuthLog
CREDMON_OAUTH = %[9]s
SEC_CREDENTIAL_STORER = %[10]s
CREDMON_OAUTH_TOKEN_MINIMUM = 600

# ----- Pelican token service "%[11]s" -----
PELICAN_CREDMON_PROVIDER_NAMES = %[11]s
PELICAN_CREDMON_TLS_SKIP_VERIFY = true
%[12]s_PELICAN_URL = %[13]s
%[12]s_PELICAN_PREFIX = %[14]s
%[12]s_PELICAN_PERMISSIONS = read, modify
# No %[12]s_PELICAN_TOKEN_URL: the credmon discovers the token endpoint via OIDC
# metadata from the issuer that minted the token.
%[12]s_PELICAN_CLIENT_ID = %[15]s
%[12]s_PELICAN_CLIENT_SECRET_FILE = %[16]s
`,
		o.tempDir, o.logDir, sbinDir, binDir, libexecDir, o.socketDir, o.pluginPath,
		o.credDir, o.credmonDaemon, o.storer, o.service, svcUpper, o.federationURL,
		o.prefix, o.clientID, o.clientSecretFile)

	return os.WriteFile(o.configFile, []byte(cfg), 0644)
}

// createCredmonClient logs in as an admin and creates an OAuth2 client with the
// token-exchange + refresh_token grants the credmon needs.
func createCredmonClient(t *testing.T, httpClient *http.Client, serverURL, adminUser, adminPassword string) (clientID, clientSecret string) {
	t.Helper()
	loginAsUser(t, httpClient, serverURL, adminUser, adminPassword)

	adminURL := serverURL + "/api/v1.0/issuer/admin/ns/credmon-test/clients"
	payload := map[string]interface{}{
		"client_name": "pelican-credmon",
		"grant_types": []string{
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"refresh_token",
		},
		"scopes": []string{"openid", "offline_access", "wlcg",
			"storage.read:/", "storage.modify:/", "storage.create:/"},
	}
	body, _ := json.Marshal(payload)
	resp, err := httpClient.Post(adminURL, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"admin client creation should return 201: %s", string(respBody))

	var created struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	require.NoError(t, json.Unmarshal(respBody, &created))
	require.NotEmpty(t, created.ClientID)
	require.NotEmpty(t, created.ClientSecret)
	return created.ClientID, created.ClientSecret
}

func loginAsUser(t *testing.T, httpClient *http.Client, serverURL, username, password string) {
	t.Helper()
	form := url.Values{"user": {username}, "password": {password}}
	resp, err := httpClient.PostForm(serverURL+"/api/v1.0/auth/login", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login as %s should succeed: %s", username, string(b))
}

// submitWithDeviceApproval runs condor_submit (which invokes the storer and its
// device-code flow), scrapes the verification URL from its combined output,
// approves it as the given web user, and returns the cluster ID.
func submitWithDeviceApproval(ctx context.Context, t *testing.T, submitFile string, env []string,
	uid, gid int, httpClient *http.Client, serverURL, approver, approverPassword string) string {
	t.Helper()

	cmd := exec.CommandContext(ctx, "condor_submit", submitFile)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}

	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	cmd.Stdout = pw
	cmd.Stderr = pw

	require.NoError(t, cmd.Start())
	pw.Close() // child holds the only remaining write end

	urlRe := regexp.MustCompile(`https?://\S+`)
	var combined bytes.Buffer
	approved := false
	scanner := bufio.NewScanner(pr)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		combined.WriteString(line + "\n")
		t.Logf("[condor_submit] %s", line)
		if approved {
			continue
		}
		if m := urlRe.FindString(line); m != "" &&
			(strings.Contains(m, "user_code=") || strings.Contains(m, "/device")) {
			verifyURL := strings.TrimRight(m, ".)\"'")
			t.Logf("Approving device code at %s", verifyURL)
			approvePelicanDeviceCode(t, httpClient, serverURL, verifyURL, approver, approverPassword)
			approved = true
		}
	}
	waitErr := cmd.Wait()
	out := combined.String()
	if waitErr != nil {
		t.Logf("condor_submit failed: %v\nOutput:\n%s", waitErr, out)
		return ""
	}
	require.True(t, approved, "did not observe a device-code verification URL in condor_submit output:\n%s", out)
	return extractClusterID(out)
}

// approvePelicanDeviceCode logs in as the approver and approves the device code
// identified by the verification URL.
func approvePelicanDeviceCode(t *testing.T, httpClient *http.Client, serverURL, verifyURL, username, password string) {
	t.Helper()

	parsed, err := url.Parse(verifyURL)
	require.NoError(t, err, "device verification URL should parse: %s", verifyURL)
	userCode := parsed.Query().Get("user_code")
	require.NotEmpty(t, userCode, "verification URL should carry a user_code: %s", verifyURL)
	// The Pelican client emits a web-UI URL of the form
	//   https://host:port/view/issuer/device?namespace=%2Fcredmon-test&user_code=XXXX-XXXX
	// The corresponding API endpoints live under
	//   https://host:port/api/v1.0/issuer/ns/<namespace>/device
	namespace := parsed.Query().Get("namespace")
	require.NotEmpty(t, namespace, "verification URL should carry a namespace: %s", verifyURL)
	namespace = "/" + strings.TrimPrefix(namespace, "/")
	origin := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	nsBase := origin + "/api/v1.0/issuer/ns" + namespace

	loginAsUser(t, httpClient, serverURL, username, password)

	// GET the verification page for a CSRF token.
	getURL := fmt.Sprintf("%s/device?user_code=%s", nsBase, url.QueryEscape(userCode))
	resp, err := httpClient.Get(getURL)
	require.NoError(t, err)
	pageBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "device-verify GET should return 200: %s", string(pageBody))

	var verifyResp struct {
		CSRFToken string `json:"csrf_token"`
	}
	require.NoError(t, json.Unmarshal(pageBody, &verifyResp))
	require.NotEmpty(t, verifyResp.CSRFToken)

	approvePayload, _ := json.Marshal(map[string]string{
		"user_code":  userCode,
		"action":     "approve",
		"csrf_token": verifyResp.CSRFToken,
	})
	resp, err = httpClient.Post(nsBase+"/device", "application/json", bytes.NewReader(approvePayload))
	require.NoError(t, err)
	approveBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "device approval should return 200: %s", string(approveBody))
}

// sighupCredmon reads the credmon's pid file and sends it SIGHUP to trigger a
// rescan.
func sighupCredmon(t *testing.T, credDir string) {
	t.Helper()
	pidFile := filepath.Join(credDir, "pid")
	require.Eventually(t, func() bool {
		_, err := os.Stat(pidFile)
		return err == nil
	}, 30*time.Second, 500*time.Millisecond, "credmon pid file should appear")
	data, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		t.Logf("Warning: failed to SIGHUP credmon pid %d: %v", pid, err)
	}
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, data, 0755))
}

func credmonRandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

func extractBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}

func accessTokenFromUse(t *testing.T, useContent string) string {
	t.Helper()
	useContent = strings.TrimSpace(useContent)
	if strings.HasPrefix(useContent, "{") {
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(useContent), &m))
		tok, _ := m["access_token"].(string)
		require.NotEmpty(t, tok, "access_token should be present in the .use JSON")
		return tok
	}
	return useContent
}

func decodeJWTClaims(t *testing.T, tokenStr string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	require.Equal(t, 3, len(parts), "expected a JWT with 3 parts")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// jtiOf decodes a JWT and returns its "jti" claim.
func jtiOf(t *testing.T, tokenStr string) string {
	return jtiFromClaims(decodeJWTClaims(t, tokenStr))
}

// jtiFromClaims returns the "jti" claim from a decoded claim set.
func jtiFromClaims(claims map[string]interface{}) string {
	if jti, ok := claims["jti"].(string); ok {
		return jti
	}
	return ""
}

func scopeString(claims map[string]interface{}) string {
	switch s := claims["scope"].(type) {
	case string:
		return s
	case []interface{}:
		parts := make([]string, 0, len(s))
		for _, v := range s {
			if str, ok := v.(string); ok {
				parts = append(parts, str)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func nsBaseIssuer(serverURL string) string {
	return serverURL + "/api/v1.0/issuer/ns/credmon-test"
}

func readJSONFile(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "should read %s", path)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m), "should parse %s as JSON", path)
	return m
}

func readJSONFileNoFail(path string) map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	return m
}

func writeJSONFile(t *testing.T, path string, obj interface{}) {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}
