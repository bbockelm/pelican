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
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests here force, with the promoter's hooks, the races between a
// promotion from a cold target and the end of the local life it promotes --
// a deletion, or eviction back to the kept cold copy -- and check that
// nothing of the ended life is left behind or written into the next one (see
// coldSource and instanceFences).

// newLocalLife deletes the object and brings it back as a new local life:
// on the cold target again, and promoted again, with a fresh data key and an
// empty bitmap.  It puts the object on the cold target directly, as an
// upload and relocation would leave it, rather than through the uploader,
// whose release of the local copy would wait for whatever copy of the old
// life the test is holding.
func (e *coldCacheEnv) newLocalLife(t *testing.T, hash InstanceHash, data []byte) *CacheMetadata {
	t.Helper()
	old, err := e.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, old)
	require.NoError(t, e.pc.storage.Delete(hash))
	remote, err := e.target.backend.Put(e.ctx, e.target.objectKey(hash), "application/octet-stream",
		int64(len(data)), bytes.NewReader(data))
	require.NoError(t, err)
	cold := *old
	cold.StorageID = e.tierID
	cold.Remote = &remote
	cold.ColdCopy = nil
	cold.ChunkSizeCode = ChunkingDisabled
	cold.ChunkLocations = nil
	require.NoError(t, e.pc.storage.SetMetadata(hash, &cold))
	return e.promoteForTest(t, hash)
}

// hasPromoteIntent reports whether the object has a PrefixTierPromote intent.
func (e *coldCacheEnv) hasPromoteIntent(t *testing.T, hash InstanceHash) bool {
	t.Helper()
	hashes, err := e.pc.db.ListTierPromoteIntents()
	require.NoError(t, err)
	return slices.Contains(hashes, hash)
}

// gate is a hook that a background goroutine runs once: it signals that it
// has reached the hook, then waits until the test lets it go on.
type gate struct {
	reached chan struct{}
	proceed chan struct{}
	once    sync.Once
}

// newGate makes a gate, which the test's end opens if the test has not:
// a test that fails while a goroutine waits at the gate must not leave the
// cache unable to close.
func newGate(t *testing.T) *gate {
	g := &gate{reached: make(chan struct{}), proceed: make(chan struct{})}
	t.Cleanup(g.open)
	return g
}

// open lets the goroutine waiting at the gate go on.
func (g *gate) open() {
	g.once.Do(func() { close(g.proceed) })
}

func (g *gate) hook(InstanceHash) {
	select {
	case <-g.reached:
		return // only the first caller waits
	default:
	}
	close(g.reached)
	<-g.proceed
}

func (g *gate) await(t *testing.T) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(20 * time.Second):
		t.Fatal("the hook was never reached")
	}
}

// TestColdTierPromotionKeepsTheFileOfARefetch checks a promotion against a
// deletion that lands after its checks and a fetch of the same version that
// creates a new local instance in the meantime -- whose file is where the
// promoted copy's would go.  The promotion must decline, leaving the new
// instance and its file alone, rather than create the file over it and then,
// failing to record the promotion, remove it.
func TestColdTierPromotionKeepsTheFileOfARefetch(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/refetched.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	p := env.pc.promoter

	fired := false
	p.hooks.beforeCreate = func(h InstanceHash) {
		if fired {
			return
		}
		fired = true
		require.NoError(t, env.pc.storage.Delete(h))
		_, err := env.pc.storage.InitDiskStorage(env.ctx, h, int64(len(data)), env.diskID, env.pc.getNamespaceID(path))
		require.NoError(t, err)
	}
	_, err := p.flip(hash, env.target)
	require.True(t, fired)
	require.ErrorIs(t, err, errPromotionDeclined)

	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "the new instance survives")
	assert.Equal(t, env.diskID, meta.StorageID)
	assert.Nil(t, meta.ColdCopy, "the new instance is not a promotion")
	info, err := os.Stat(env.pc.storage.getObjectPathForDir(env.diskID, hash))
	require.NoError(t, err, "the promotion removed the new instance's file")
	assert.Equal(t, CalculateFileSize(int64(len(data))), info.Size())
	assert.Zero(t, env.pc.storage.fences.size())
}

// TestColdTierCopyWritesNothingIntoANewLocalLife checks a copy from the cold
// copy whose object is deleted and promoted again just after the copy has
// checked its local life, and before it makes its writer.  The copy belongs
// to the life that ended, and must write nothing into the new one.
func TestColdTierCopyWritesNothingIntoANewLocalLife(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/relived.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	env.promoteForTest(t, hash)
	p := env.pc.promoter

	g := newGate(t)
	p.hooks.beforeWriter = g.hook
	done := env.coldFill(t, p, hash, 0, 10)
	g.await(t)
	second := env.newLocalLife(t, hash, data)
	g.open()
	awaitFill(t, done)

	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	require.True(t, bytes.Equal(second.DataKey, meta.DataKey))
	assert.Empty(t, env.presentBlocks(t, hash), "a copy for the ended local life wrote blocks of the new one")
	require.Eventually(t, func() bool { return env.pc.storage.fences.size() == 0 },
		10*time.Second, 10*time.Millisecond, "no fence may outlive its writers")
}

// TestColdTierCondemnedCopyDropsOnlyItsOwnLife checks a copy that condemns the
// object -- here a cold copy shorter than its record -- against a deletion and
// a new promotion of the object that land before it drops what it condemned.
// The drop is for the copy's own local life; the new one must survive.
func TestColdTierCondemnedCopyDropsOnlyItsOwnLife(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/condemned.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	env.promoteForTest(t, hash)
	short := data[:40*BlockDataSize+77]
	_, err := env.target.backend.Put(env.ctx, env.target.objectKey(hash), "application/octet-stream",
		int64(len(short)), bytes.NewReader(short))
	require.NoError(t, err)
	p := env.pc.promoter

	g := newGate(t)
	p.hooks.beforeCondemnedDelete = g.hook
	done := env.coldFill(t, p, hash, 0, 63)
	g.await(t)
	second := env.newLocalLife(t, hash, data)
	g.open()
	awaitFill(t, done)

	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "a copy of the ended local life dropped the new one")
	assert.True(t, bytes.Equal(second.DataKey, meta.DataKey))
	assert.NotNil(t, meta.ColdCopy)
}

// TestColdTierBackgroundCopyRecordsNoIntentForADeletedObject checks the
// background copy's PrefixTierPromote intent against a deletion of the object
// just before it is recorded: an intent recorded then would be a row of an
// object that is gone.
func TestColdTierBackgroundCopyRecordsNoIntentForADeletedObject(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/intent.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	meta := env.promoteForTest(t, hash)
	p := env.pc.promoter

	p.hooks.beforeIntent = func(h InstanceHash) { require.NoError(t, env.pc.storage.Delete(h)) }
	p.startBackgroundFill(hash, meta)

	assert.False(t, env.hasPromoteIntent(t, hash), "an intent was recorded for a deleted object")
	p.mu.Lock()
	assert.Empty(t, p.background)
	p.mu.Unlock()
	assert.Zero(t, env.pc.storage.fences.size())
}

// TestColdTierBackgroundCopyKeepsTheIntentOfANewLife checks the other end of
// the intent: a background copy that finished for a local life that then
// ends, and is followed by a new promotion with a copy of its own, must not
// clear the new copy's intent.
func TestColdTierBackgroundCopyKeepsTheIntentOfANewLife(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/intent-cleared.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	meta := env.promoteForTest(t, hash)
	p := env.pc.promoter

	g := newGate(t)
	p.hooks.beforeIntentCleared = g.hook
	p.startBackgroundFill(hash, meta)
	g.await(t)
	env.newLocalLife(t, hash, data)
	// What the new life's background copy records when it starts.
	require.NoError(t, env.pc.db.SetTierPromoteIntent(hash))
	g.open()
	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.background) == 0
	}, 10*time.Second, 10*time.Millisecond, "the first copy should finish")

	assert.True(t, env.hasPromoteIntent(t, hash), "the copy of the ended local life cleared the new one's intent")
}

// TestColdTierRecoveryKeepsTheIntentOfAPromotionSinceStarted checks crash
// recovery against a read that promotes an object while recovery is deciding
// the object's leftover intent is stale: the intent is the new promotion's by
// then, and must be kept.
func TestColdTierRecoveryKeepsTheIntentOfAPromotionSinceStarted(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/recovered.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	// Left over from an earlier promotion; the object is on the cold
	// target, so recovery finds it stale.
	require.NoError(t, env.pc.db.SetTierPromoteIntent(hash))

	p := makeTierPromoter(env.pc, env.pc.downloadCtx)
	fired := false
	p.hooks.beforeStaleIntentDropped = func(h InstanceHash) {
		if fired {
			return
		}
		fired = true
		env.promoteForTest(t, h)
		require.NoError(t, env.pc.db.SetTierPromoteIntent(h))
	}
	p.recover()
	require.True(t, fired)
	assert.True(t, env.hasPromoteIntent(t, hash), "recovery dropped the intent of a promotion begun since it looked")

	// Without the race, recovery drops a stale intent.
	require.NoError(t, env.pc.storage.Delete(hash))
	require.NoError(t, env.pc.db.SetTierPromoteIntent(hash))
	p.recover()
	assert.False(t, env.hasPromoteIntent(t, hash))
}

// TestColdTierEvictionToTheKeptCopyFencesAWriter checks that eviction pointing
// a promoted object back at its kept cold copy ends the local life for its
// writers, as a deletion does: a writer of that life still running -- here
// one with blocks waiting in its batch -- writes nothing afterwards, not even
// once the object has been promoted again, when its blocks, encrypted under
// the old life's key, would otherwise be marked present in the new life.
func TestColdTierEvictionToTheKeptCopyFencesAWriter(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/evicted.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	env.promoteForTest(t, hash)
	require.NoError(t, env.pc.eviction.RecordAccess(hash))

	bw, err := env.pc.storage.NewBlockWriter(hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(data[:3*BlockDataSize])
	require.NoError(t, err)

	evicted, _, _, err := env.pc.storage.EvictByLRU(env.diskID, env.pc.getNamespaceID(path), 0, 0)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	require.Equal(t, env.tierID, evicted[0].demotedTo, "the object went back to its kept copy")
	second := env.promoteForTest(t, hash)

	bw.StopEarly() // flushes the whole blocks in its batch
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.True(t, bytes.Equal(second.DataKey, meta.DataKey))
	assert.Empty(t, env.presentBlocks(t, hash), "a writer of the evicted local life marked blocks of the new one")
	env.checkPresentBlocks(t, hash, data)
	assert.Zero(t, env.pc.storage.fences.size())
}
