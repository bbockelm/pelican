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

package local_cache

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTierReapsStaleUploads runs the stale-upload reaper against a real S3
// server, one upload per page so that it has to page: it aborts only
// uploads under the target's prefix and older than the cutoff, and it gets
// through every page.
func TestTierReapsStaleUploads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	backend, ok := env.target.backend.(*blobTierBackend)
	require.True(t, ok)
	require.NotNil(t, backend.s3Client)
	client, bucket := backend.s3Client, backend.s3Bucket
	backend.reapPageSize = 1

	start := func(key string) {
		_, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: &bucket, Key: aws.String(key),
		})
		require.NoError(t, err)
	}
	pending := func(prefix string) []string {
		out, err := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket, Prefix: aws.String(prefix),
		})
		require.NoError(t, err)
		var keys []string
		for _, up := range out.Uploads {
			keys = append(keys, aws.ToString(up.Key))
		}
		sort.Strings(keys)
		return keys
	}

	// Two abandoned uploads of one key, so one page boundary falls inside
	// that key's uploads; and one outside the target's prefix, which
	// belongs to someone else.
	inTarget := []string{"cache/00/01/a", "cache/00/01/b", "cache/00/01/b", "cache/00/01/c"}
	for _, key := range inTarget {
		start(key)
	}
	start("elsewhere/x")

	// Nothing is older than an hour.
	reaped, err := backend.ReapStaleUploads(ctx, time.Hour)
	require.NoError(t, err)
	assert.Zero(t, reaped)
	assert.Equal(t, inTarget, pending("cache/"))

	// With no age limit every upload in the target is stale.  Paging by
	// key leaves the second upload of a key that straddles a page boundary
	// for the next pass.
	reaped, err = backend.ReapStaleUploads(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, 3, reaped)
	reaped, err = backend.ReapStaleUploads(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, reaped)
	assert.Empty(t, pending("cache/"))
	assert.Equal(t, []string{"elsewhere/x"}, pending("elsewhere/"))
}
