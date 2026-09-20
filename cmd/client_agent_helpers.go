//go:build client

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

import (
	"context"
	"net/http"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/config"
)

// asyncWarmItem identifies a remote object whose credential should be ensured
// in the wallet before an asynchronous submission to the client agent.
type asyncWarmItem struct {
	url   string
	write bool
}

// warmWalletForAsync ensures the user's wallet holds usable tokens for the
// given remote objects (acquiring them interactively if needed) and then opens
// the agent's wallet so the agent can use and refresh them while the job runs.
//
// The client agent runs without a controlling terminal and cannot perform
// interactive token acquisition, so the (interactive) CLI warms the wallet on
// its behalf before submitting. Public namespaces that require no token are
// skipped; if none of the objects needs a token, the agent wallet is left
// untouched.
func warmWalletForAsync(ctx context.Context, apiClient *apiclient.APIClient, items []asyncWarmItem) error {
	warmedAny := false
	for _, it := range items {
		needed, err := warmOneCredential(ctx, it.url, it.write)
		if err != nil {
			return err
		}
		warmedAny = warmedAny || needed
	}
	if !warmedAny {
		return nil
	}

	// Forward the wallet password (cached while acquiring above) to the agent
	// so it can decrypt, use, and refresh the stored credentials.
	password, _ := config.TryGetPassword()
	if err := apiClient.OpenWallet(ctx, string(password)); err != nil {
		return errors.Wrap(err, "failed to open the agent's credential wallet")
	}
	return nil
}

// warmOneCredential ensures a usable token for a single remote object is in the
// wallet, acquiring one interactively if necessary. It reports whether the
// object's namespace required a token at all.
func warmOneCredential(ctx context.Context, rawURL string, write bool) (needed bool, err error) {
	pUrl, err := client.ParseRemoteAsPUrl(ctx, rawURL)
	if err != nil {
		return false, errors.Wrapf(err, "failed to parse %q", rawURL)
	}

	httpMethod := http.MethodGet
	var operation config.TokenOperation
	operation.Set(config.TokenRead)
	operation.Set(config.TokenList)
	if write {
		operation.Set(config.TokenWrite)
		operation.Set(config.TokenDelete)
		httpMethod = http.MethodPut
	}

	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, httpMethod, "")
	if err != nil {
		return false, errors.Wrapf(err, "director lookup failed for %q", rawURL)
	}
	if !dirResp.XPelNsHdr.RequireToken {
		return false, nil
	}

	opts := config.TokenGenerationOpts{
		Operation:    operation,
		DiscoveryURL: pUrl.FedInfo.DiscoveryEndpoint,
	}
	if _, err := client.AcquireToken(pUrl.GetRawUrl(), dirResp, opts); err != nil {
		return true, errors.Wrapf(err, "failed to acquire a credential for %q", rawURL)
	}
	return true, nil
}

// ensureClientAgentRunning ensures the client agent is running, starting it if
// necessary, and returns a client connected to it.
func ensureClientAgentRunning(ctx context.Context, maxRetries int) (*apiclient.APIClient, error) {
	return apiclient.EnsureRunning(ctx, maxRetries)
}
