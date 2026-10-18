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

package transfer_records

import (
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/metrics"
)

func testIdentity() ServerIdentity {
	return ServerIdentity{
		Name: "cache.example.org", ServerType: "Cache",
		Version: "v7.0.0", Federation: "https://osg-htc.org",
	}
}

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Config{
		Dir: t.TempDir(), Identity: testIdentity(),
		RotateInterval: -1, MaintainInterval: -1, // driven explicitly in tests
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func sampleEvent() metrics.TransferEvent {
	start := time.Now().Add(-250 * time.Millisecond)
	return metrics.TransferEvent{
		Path: "/ospool/public/data.root", ReadBytes: 4096, ReadOps: 3,
		ClientIP: "192.0.2.10", UserDN: "alice", AuthProtocol: "https",
		Project: "MyProject", StartTime: start, EndTime: time.Now(),
	}
}

func TestRecordProjection(t *testing.T) {
	ad := recordFromEvent(sampleEvent(), testIdentity(), StatusCompleted, "xfer-1")

	str := func(attr string) string {
		v, ok := ad.EvaluateAttrString(attr)
		require.True(t, ok, attr)
		return v
	}
	num := func(attr string) int {
		v, ok := ad.EvaluateAttrInt(attr)
		require.True(t, ok, attr)
		return int(v)
	}

	assert.Equal(t, "/ospool/public/data.root", str(AttrPath))
	assert.Equal(t, StatusCompleted, str(AttrStatus))
	assert.Equal(t, "alice", str(AttrUserDN))
	assert.Equal(t, "MyProject", str(AttrProject))
	assert.Equal(t, 4096, num(AttrReadBytes))
	assert.Equal(t, 3, num(AttrReadOps))
	assert.NotZero(t, num(AttrCompletionDate), "records must be time-stamped for the archive's zone map")

	// Identity travels with the record so a collector need not join against
	// whatever it knows about its sources.
	assert.Equal(t, "cache.example.org", str(AttrServerName))
	assert.Equal(t, "Cache", str(AttrServerType))
	assert.Equal(t, "https://osg-htc.org", str(AttrFederation))

	// A sub-second transfer must not record a zero duration.
	dur, ok := ad.EvaluateAttrReal(AttrDurationSecs)
	require.True(t, ok)
	assert.Greater(t, dur, 0.0)
	assert.Less(t, dur, 1.0)
}

// TestUnknownFieldsAreOmitted checks that a field Pelican did not measure is
// absent rather than present-and-empty, so a collector can tell "not known" from
// "known to be blank".
func TestUnknownFieldsAreOmitted(t *testing.T) {
	ad := recordFromEvent(metrics.TransferEvent{Path: "/x"}, ServerIdentity{}, StatusCompleted, "k")
	for _, attr := range []string{AttrUserDN, AttrProject, AttrIssuer, AttrServerName, AttrWriteBytes} {
		_, ok := ad.EvaluateAttrString(attr)
		assert.False(t, ok, "%s should be absent when unknown", attr)
	}
}

func TestRecordAppendsToArchive(t *testing.T) {
	s := openStore(t)
	s.Record(sampleEvent())
	s.Record(sampleEvent())

	stats := s.Stats()
	assert.EqualValues(t, 2, stats.Appended)
	assert.Equal(t, 2, stats.ArchiveCount)
	assert.Equal(t, 0, stats.ActiveCount, "a completed transfer leaves nothing in progress")
}

func TestActiveLifecycle(t *testing.T) {
	s := openStore(t)
	event := sampleEvent()

	key := s.BeginActive(event)
	require.NotEmpty(t, key)
	assert.Equal(t, 1, s.Stats().ActiveCount)

	event.ReadBytes = 8192
	s.UpdateActive(key, event)
	assert.Equal(t, 1, s.Stats().ActiveCount, "an update must not create a second row")

	s.CompleteActive(key, event)
	assert.Equal(t, 0, s.Stats().ActiveCount)
	assert.Equal(t, 1, s.Stats().ArchiveCount)
}

// TestReconcileRecoversAbandonedTransfers is the crash-recovery property: rows
// left in the in-progress table can only come from a server that stopped while
// transfers were running, and they must be accounted for rather than dropped.
func TestReconcileRecoversAbandonedTransfers(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, Identity: testIdentity(), RotateInterval: -1, MaintainInterval: -1}

	first, err := Open(cfg)
	require.NoError(t, err)
	first.BeginActive(sampleEvent())
	require.Equal(t, 1, first.Stats().ActiveCount)
	require.NoError(t, first.Close()) // the server "crashes" with a transfer in flight

	second, err := Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, second.Close()) }()

	n, err := second.Reconcile()
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 0, second.Stats().ActiveCount)
	assert.Equal(t, 1, second.Stats().ArchiveCount,
		"an interrupted transfer must survive as a record, not vanish")

	// And it is marked as abandoned rather than silently presented as completed.
	require.NoError(t, second.EachArchived(func(ad *classad.ClassAd) {
		status, ok := ad.EvaluateAttrString(AttrStatus)
		require.True(t, ok)
		assert.Equal(t, StatusAbandoned, status)
	}))
}

func TestReconcileIsNoOpWhenNothingWasRunning(t *testing.T) {
	s := openStore(t)
	n, err := s.Reconcile()
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestRecordsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, Identity: testIdentity(), RotateInterval: -1, MaintainInterval: -1}

	first, err := Open(cfg)
	require.NoError(t, err)
	first.Record(sampleEvent())
	require.NoError(t, first.Close())

	second, err := Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, second.Close()) }()
	assert.Equal(t, 1, second.Stats().ArchiveCount, "the archive must be durable across a restart")
}

func TestOpenRequiresADirectory(t *testing.T) {
	_, err := Open(Config{})
	require.Error(t, err)
}

// TestStoreAsActiveObserver drives the store through the metrics observer
// interface, the way a running server does, rather than by calling its methods
// directly.
//
// The property under test is that one transfer produces exactly one archived
// record. The store is registered as an observer rather than a consumer
// precisely because it archives the record itself at completion; registering it
// as both would double-count every transfer, and nothing but a test would
// notice until the numbers were wrong.
func TestStoreAsActiveObserver(t *testing.T) {
	s := openStore(t)

	var observer metrics.ActiveTransferObserver = s
	metrics.RegisterActiveTransferObserver("test-store", observer)
	defer metrics.UnregisterActiveTransferObserver("test-store")

	event := sampleEvent()
	metrics.EmitTransferEvent(event)

	stats := s.Stats()
	assert.Equal(t, 1, stats.ArchiveCount, "one transfer must archive exactly one record")
	assert.Equal(t, 0, stats.ActiveCount, "a finished transfer must leave no in-progress row")
}

// TestActiveRowVisibleDuringTransfer covers the other half of the two-table
// split: while a transfer runs it is visible, and it is not yet in the archive.
func TestActiveRowVisibleDuringTransfer(t *testing.T) {
	s := openStore(t)
	event := sampleEvent()

	key := s.BeginActive(event)
	assert.Equal(t, 1, s.Stats().ActiveCount, "a running transfer should be visible")
	assert.Equal(t, 0, s.Stats().ArchiveCount, "a running transfer is not yet history")

	s.CompleteActive(key, event)
	assert.Equal(t, 0, s.Stats().ActiveCount)
	assert.Equal(t, 1, s.Stats().ArchiveCount)
}
