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

package local_cache

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/metrics"
)

// TestTierRedirectSelfTest covers the check that stands between minting URLs
// and handing them out.  The fake door here speaks dCache's macaroon protocol
// but checks path: caveats the way XRootD does, without the name: caveat that
// would give it away -- a server the cache's model of dCache is wrong about.
// Every URL minted for it would fail at the server, so the target must be
// proxied, visibly; and once the server behaves, redirects resume.
func TestTierRedirectSelfTest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("WorkingURLsAreHandedOut", func(t *testing.T) {
		f := newFakeDCache(t)
		target := registerFakeDCacheTarget(t, ctx, f)
		assert.True(t, target.redirectUsable())
		assert.Equal(t, 1.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))
		_, reads, _ := f.stats()
		assert.Equal(t, 1, reads, "the self-test fetched a minted URL")
	})

	t.Run("FailingURLsAreNot", func(t *testing.T) {
		f := newFakeDCache(t)
		f.set(func(f *fakeDCache) { f.xrootd = true })
		target := registerFakeDCacheTarget(t, ctx, f)
		assert.True(t, target.canRedirect, "the door issues macaroons the cache can parse...")
		assert.False(t, target.redirectUsable(), "...but the URLs minted from them do not work")
		assert.Equal(t, 0.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))
		lastErr, _ := target.lastRedirectError.Load().(string)
		assert.Contains(t, lastErr, "403")
		assert.NotContains(t, lastErr, "authz", "the minted URL must not reach the log")

		// The health component says why the target is being proxied.
		u := &tierUploader{storage: &StorageManager{tierTargets: map[StorageID]*tierTarget{target.id: target}}}
		u.publishHealth()
		status, err := metrics.GetComponentStatus(metrics.Cache_TieringStorage)
		require.NoError(t, err)
		assert.Equal(t, metrics.StatusWarning.String(), status)
		message := metrics.GetHealthStatus().ComponentStatus[metrics.Cache_TieringStorage].Message
		assert.Contains(t, message, "redirect URLs do not work")

		// Once the server accepts the URLs, the next check restores
		// redirects.
		f.set(func(f *fakeDCache) { f.xrootd = false })
		require.NoError(t, target.checkRedirect(ctx))
		assert.True(t, target.redirectUsable())
		assert.Equal(t, 1.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))
		u.publishHealth()
		status, err = metrics.GetComponentStatus(metrics.Cache_TieringStorage)
		require.NoError(t, err)
		assert.Equal(t, metrics.StatusOK.String(), status)
	})
}
