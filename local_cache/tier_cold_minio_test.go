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
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/test_utils"
)

// newMinioColdCache is newColdCache against a cold S3 target on minio.
func newMinioColdCache(t *testing.T, bucket string) *coldCacheEnv {
	t.Helper()
	test_utils.SkipIfNoMinio(t)
	endpoint, accessKey, secretKey := test_utils.StartMinio(t, bucket)
	keyDir := t.TempDir()
	accessKeyfile := filepath.Join(keyDir, "access")
	secretKeyfile := filepath.Join(keyDir, "secret")
	require.NoError(t, os.WriteFile(accessKeyfile, []byte(accessKey), 0600))
	require.NoError(t, os.WriteFile(secretKeyfile, []byte(secretKey), 0600))
	return newColdCacheWith(t, 0, map[string]interface{}{
		"ServiceUrl":    endpoint,
		"Bucket":        bucket,
		"Prefix":        "cold",
		"MaxSize":       "1GB",
		"AccessKeyfile": accessKeyfile,
		"SecretKeyfile": secretKeyfile,
		"Cold":          true,
	})
}

// TestColdTierOnMinio runs the cold-tier round trip against a real S3
// implementation: an object demoted to the bucket is promoted back by a read
// (whole and ranged), served correctly while it fills, and demoted again by
// eviction without being uploaded a second time.
func TestColdTierOnMinio(t *testing.T) {
	env := newMinioColdCache(t, "pelican-cold-test")

	const path = "/test/cold/minio.bin"
	data := coldTestData(5<<20 + 4321)
	hash := env.putColdObject(t, path, data)

	const start, end = 3000000, 3100000
	status, body := env.get(t, path, fmt.Sprintf("bytes=%d-%d", start, end))
	require.Equal(t, http.StatusPartialContent, status)
	require.True(t, bytes.Equal(data[start:end+1], body))

	status, body = env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body))
	meta := env.waitPromoted(t, hash)
	assert.Equal(t, env.diskID, meta.StorageID)
	require.NotNil(t, meta.ColdCopy)
	assert.NotEmpty(t, meta.ColdCopy.Remote.ETag, "S3 records an entity tag for the kept copy")

	evicted, _, _, err := env.pc.storage.EvictByLRU(env.diskID, env.pc.getNamespaceID(path), 0, 0)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	assert.Equal(t, env.tierID, evicted[0].demotedTo)

	status, body = env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body), "the object read back from its kept copy")
	env.waitPromoted(t, hash)
}

// TestColdTierChangedCopyDuringPromotion checks that a cold copy found
// overwritten while it is being promoted from is dropped, rather than its
// bytes being copied into the local object.  It needs S3: reads are pinned to
// the recorded copy with If-Match, which the in-memory driver cannot do.
func TestColdTierChangedCopyDuringPromotion(t *testing.T) {
	env := newMinioColdCache(t, "pelican-cold-changed")
	const path = "/test/cold/changed.bin"
	data := coldTestData(64 * 1024)
	hash := env.putColdObject(t, path, data)
	_, err := env.target.backend.Put(env.ctx, env.target.objectKey(hash), "application/octet-stream",
		int64(len(data)), bytes.NewReader(make([]byte, len(data))))
	require.NoError(t, err)

	_, err = env.pc.promoter.flip(hash, env.target)
	require.NoError(t, err)
	awaitFill(t, env.coldFill(t, env.pc.promoter, hash, 0, 0))

	require.Eventually(t, func() bool {
		meta, err := env.pc.storage.GetMetadata(hash)
		return err == nil && meta != nil && meta.ColdCopy == nil
	}, 10*time.Second, 10*time.Millisecond, "the changed copy should be dropped")
	bs, err := env.pc.storage.GetSharedBlockState(hash)
	require.NoError(t, err)
	assert.Zero(t, bs.GetCardinality(), "nothing from the changed copy was written locally")
	assert.Zero(t, env.usage(t, env.tierID, path), "the dropped copy is refunded")
}
