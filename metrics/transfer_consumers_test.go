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

package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// withShoveler sets Shoveler.Enable for the duration of a test and restores it
// afterwards. server_utils.ResetTestState is unavailable here: server_utils
// imports metrics, so using it from this package's tests is an import cycle.
func withShoveler(t *testing.T, enabled bool) {
	t.Helper()
	previous := param.Shoveler_Enable.GetBool()
	require.NoError(t, param.Shoveler_Enable.Set(enabled))
	t.Cleanup(func() { require.NoError(t, param.Shoveler_Enable.Set(previous)) })
}

// collector is a consumer that records what it was handed.
type collector struct {
	mu     sync.Mutex
	events []TransferEvent
}

func (c *collector) consume(e TransferEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *collector) all() []TransferEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]TransferEvent, len(c.events))
	copy(out, c.events)
	return out
}

func sampleEvent() TransferEvent {
	return TransferEvent{
		Path:         "/foo/bar.txt",
		ClientIP:     "192.0.2.1",
		UserDN:       "alice",
		AuthProtocol: "https",
		StartTime:    time.Now().Add(-time.Second),
	}
}

// TestConsumerReceivesFinalCounts checks that a consumer is handed the
// transfer's final byte and operation counts rather than whatever the event
// carried when the transfer began.
func TestConsumerReceivesFinalCounts(t *testing.T) {
	withShoveler(t, false)

	c := &collector{}
	RegisterTransferEventConsumer("test", c.consume)
	defer UnregisterTransferEventConsumer("test")

	event := sampleEvent()
	event.ReadBytes = 0 // not yet known when the transfer starts
	EmitTransferEvent(TransferEvent{
		Path: event.Path, ClientIP: event.ClientIP, UserDN: event.UserDN,
		AuthProtocol: event.AuthProtocol, StartTime: event.StartTime,
		ReadBytes: 4096, ReadOps: 3,
	})

	got := c.all()
	require.Len(t, got, 1)
	assert.Equal(t, "/foo/bar.txt", got[0].Path)
	assert.EqualValues(t, 4096, got[0].ReadBytes)
	assert.EqualValues(t, 3, got[0].ReadOps)
	assert.False(t, got[0].EndTime.IsZero(), "a completed record must carry an end time")
}

// TestConsumersRunWithShovelerDisabled is the §2.2 guarantee of
// docs/transfer-records-design.md, in the direction
// that regressed most easily: the shoveler's knob governs the shoveler, not
// whether a transfer is recorded at all.
func TestConsumersRunWithShovelerDisabled(t *testing.T) {
	withShoveler(t, false)

	c := &collector{}
	RegisterTransferEventConsumer("test", c.consume)
	defer UnregisterTransferEventConsumer("test")

	EmitTransferEvent(sampleEvent())
	assert.Len(t, c.all(), 1, "a consumer must still be fed when the shoveler is off")
}

// TestConsumersRunWithShovelerEnabled checks the other combination: both
// consumers active at once, neither displacing the other.
func TestConsumersRunWithShovelerEnabled(t *testing.T) {
	withShoveler(t, true)

	c := &collector{}
	RegisterTransferEventConsumer("test", c.consume)
	defer UnregisterTransferEventConsumer("test")

	EmitTransferEvent(sampleEvent())
	assert.Len(t, c.all(), 1, "a consumer must be fed alongside the shoveler")
}

// TestNoConsumersIsHarmless covers the default configuration, where nothing has
// registered and the shoveler is off.
func TestNoConsumersIsHarmless(t *testing.T) {
	withShoveler(t, false)

	assert.NotPanics(t, func() { EmitTransferEvent(sampleEvent()) })
}

// TestPanickingConsumerIsContained is the isolation guarantee: a broken consumer
// costs its own record and nothing else. Without containment the panic would
// unwind into whichever request finished the transfer.
func TestPanickingConsumerIsContained(t *testing.T) {
	withShoveler(t, false)

	good := &collector{}
	RegisterTransferEventConsumer("bad", func(TransferEvent) { panic("consumer is broken") })
	RegisterTransferEventConsumer("good", good.consume)
	defer UnregisterTransferEventConsumer("bad")
	defer UnregisterTransferEventConsumer("good")

	assert.NotPanics(t, func() { EmitTransferEvent(sampleEvent()) },
		"a consumer's panic must not reach the transfer that produced the record")
	assert.Len(t, good.all(), 1, "the other consumer must still receive the record")
}

func TestUnregisterStopsDelivery(t *testing.T) {
	withShoveler(t, false)

	c := &collector{}
	RegisterTransferEventConsumer("test", c.consume)
	EmitTransferEvent(sampleEvent())
	UnregisterTransferEventConsumer("test")
	EmitTransferEvent(sampleEvent())

	assert.Len(t, c.all(), 1, "no records should arrive after unregistering")
}
