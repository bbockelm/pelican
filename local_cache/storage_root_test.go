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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func newRootTestStorage(t *testing.T) (*CacheDB, *StorageManager, string) {
	t.Helper()
	InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	db, err := NewCacheDB(ctx, dir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	egrp, _ := errgroup.WithContext(ctx)
	sm, err := NewStorageManager(db, []string{dir}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(sm.Close)
	return db, sm, dir
}

// TestStorageRootRefusesEscapingSymlink: object files are reached through an
// os.Root on the objects directory, so a symlink planted in the fan-out tree
// cannot redirect a read or a write to somewhere else on the host.
func TestStorageRootRefusesEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	_, sm, dir := newRootTestStorage(t)

	hash := mustInstanceHash("abcd" + "000000000000000000000000000000000000000000000000000000000001")

	// objects/ab -> a directory outside the store holding cd/<rest>.
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(outside, "cd"), 0750))
	victim := filepath.Join(outside, "cd", hash.String()[4:])
	require.NoError(t, os.WriteFile(victim, []byte("not the cache's"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, objectsSubDir, "ab")))

	_, err := sm.openChunkFile(StorageIDFirstDisk, hash, 0, os.O_RDWR)
	assert.Error(t, err, "opening through a symlink that leaves the store must fail")

	_, err = sm.createChunkFile(StorageIDFirstDisk, hash, 0)
	assert.Error(t, err, "creating through a symlink that leaves the store must fail")

	assert.Error(t, sm.removeChunkFile(StorageIDFirstDisk, hash, 0), "so must removing through it")
	data, err := os.ReadFile(victim)
	require.NoError(t, err, "the file outside the store must survive")
	assert.Equal(t, "not the cache's", string(data))
}

// TestStorageRootUnknownDirectory: a storage ID with no directory is never
// resolved to some other directory; it reads as a missing file.
func TestStorageRootUnknownDirectory(t *testing.T) {
	_, sm, _ := newRootTestStorage(t)
	hash := testInstanceHash(7)

	_, err := sm.openChunkFile(StorageID(200), hash, 0, os.O_RDWR|os.O_CREATE)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = sm.statChunkFile(StorageID(200), hash, 0)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.NoError(t, sm.removeChunkFile(StorageID(200), hash, 0))
}

// TestStorageRootReadOnlyMissingDirectory: an offline tool opening a store
// whose directory is not mounted still starts, and the directory's objects
// read as missing.
func TestStorageRootReadOnlyMissingDirectory(t *testing.T) {
	db, sm, dir := newRootTestStorage(t)
	hash := testInstanceHash(8)
	f, err := sm.createChunkFile(StorageIDFirstDisk, hash, 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	sm.Close()

	require.NoError(t, os.RemoveAll(filepath.Join(dir, objectsSubDir)))
	ro, err := NewStorageManagerReadOnly(dir, db)
	require.NoError(t, err)
	t.Cleanup(ro.Close)

	_, err = ro.statChunkFile(StorageIDFirstDisk, hash, 0)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	usage := ro.DiskUsage()
	assert.Zero(t, usage.TotalFiles)
}

// TestObjectIsResolvableChecksEveryChunk: a chunked object with a chunk on a
// directory that has since been removed from the configuration is a miss --
// re-fetched, rather than failing every read -- even though its base storage
// ID still resolves.
func TestObjectIsResolvableChecksEveryChunk(t *testing.T) {
	_, sm, _ := newRootTestStorage(t)
	const removed = StorageID(3)
	chunked := func(locations ...StorageID) *CacheMetadata {
		meta := &CacheMetadata{
			StorageID:     StorageIDFirstDisk,
			ContentLength: int64(len(locations)+1) * (4 << 20),
			ChunkSizeCode: BytesToChunkSizeCode(4 << 20),
		}
		for _, id := range locations {
			meta.ChunkLocations = append(meta.ChunkLocations, ChunkLocation{StorageID: id})
		}
		return meta
	}

	assert.True(t, sm.objectIsResolvable(&CacheMetadata{StorageID: StorageIDFirstDisk}))
	assert.True(t, sm.objectIsResolvable(&CacheMetadata{StorageID: StorageIDInline}))
	assert.False(t, sm.objectIsResolvable(&CacheMetadata{StorageID: removed}))

	assert.True(t, sm.objectIsResolvable(chunked(StorageIDFirstDisk, StorageIDFirstDisk)))
	assert.True(t, sm.objectIsResolvable(chunked(StorageIDFirstDisk, StorageIDInline)),
		"an unallocated chunk is not stored anywhere yet")
	assert.False(t, sm.objectIsResolvable(chunked(StorageIDFirstDisk, removed)),
		"a chunk on a removed directory makes the whole object unreadable")

	// And the failure the check prevents: the chunk cannot be opened, nor
	// recreated, anywhere.
	hash := testInstanceHash(9)
	meta := chunked(removed)
	_, err := sm.getChunkFile(hash, meta, 1)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = sm.createChunkFile(removed, hash, 1)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// TestStorageSymlinkCheckAtStartup: a fan-out directory that is a symlink the
// root cannot follow -- an operator spreading one storage directory over
// several disks -- is refused when the cache starts, with an error that says
// why, instead of every read beneath it failing later.  A symlink that stays
// inside the tree is followed, so it is accepted.
func TestStorageSymlinkCheckAtStartup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	InitIssuerKeyForTests(t)

	start := func(t *testing.T, plant func(objects string)) error {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		dir := t.TempDir()
		objects := filepath.Join(dir, objectsSubDir)
		require.NoError(t, os.MkdirAll(objects, 0750))
		plant(objects)
		db, err := NewCacheDB(ctx, dir)
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })
		egrp, _ := errgroup.WithContext(ctx)
		sm, err := NewStorageManager(db, []string{dir}, 0, egrp)
		if err == nil {
			sm.Close()
		}
		return err
	}

	t.Run("FanOutToAnotherDisk", func(t *testing.T) {
		other := t.TempDir()
		err := start(t, func(objects string) {
			require.NoError(t, os.Symlink(other, filepath.Join(objects, "ab")))
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symbolic link")
	})

	t.Run("SecondLevel", func(t *testing.T) {
		other := t.TempDir()
		err := start(t, func(objects string) {
			require.NoError(t, os.MkdirAll(filepath.Join(objects, "ab"), 0750))
			require.NoError(t, os.Symlink(other, filepath.Join(objects, "ab", "cd")))
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symbolic link")
	})

	t.Run("AbsoluteBackInside", func(t *testing.T) {
		err := start(t, func(objects string) {
			require.NoError(t, os.MkdirAll(filepath.Join(objects, "aa"), 0750))
			require.NoError(t, os.Symlink(filepath.Join(objects, "aa"), filepath.Join(objects, "ab")))
		})
		require.Error(t, err, "os.Root refuses absolute links even into the tree")
	})

	t.Run("RelativeInsideIsFine", func(t *testing.T) {
		err := start(t, func(objects string) {
			require.NoError(t, os.MkdirAll(filepath.Join(objects, "aa"), 0750))
			require.NoError(t, os.Symlink("aa", filepath.Join(objects, "ab")))
		})
		assert.NoError(t, err)
	})
}
