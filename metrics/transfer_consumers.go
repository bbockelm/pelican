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

	log "github.com/sirupsen/logrus"
)

// TransferEventConsumer receives a record of a completed transfer.
//
// A consumer is called on the goroutine that finished the transfer, so it must
// return promptly: hand the record to a buffer or a background writer rather
// than doing I/O inline. It receives its own copy of the event and may retain
// it.
type TransferEventConsumer func(TransferEvent)

var (
	transferConsumersMu sync.RWMutex
	transferConsumers   = map[string]TransferEventConsumer{}
)

// RegisterTransferEventConsumer adds a consumer of completed transfer records,
// replacing any consumer previously registered under the same name.
//
// Consumers are independent of one another and of the XRootD-format monitoring
// stream: each gets its own copy of the record, none can prevent another from
// running, and a consumer that panics is dropped for that record with the panic
// logged rather than taking down the transfer that produced it. That isolation
// is the point -- transfer recording must never be able to break serving data.
//
// Registration is expected during startup. A consumer registered while
// transfers are in flight simply starts receiving records from the next one.
func RegisterTransferEventConsumer(name string, consumer TransferEventConsumer) {
	if consumer == nil {
		return
	}
	transferConsumersMu.Lock()
	defer transferConsumersMu.Unlock()
	transferConsumers[name] = consumer
}

// UnregisterTransferEventConsumer removes a consumer. It is a no-op if no
// consumer is registered under the name.
func UnregisterTransferEventConsumer(name string) {
	transferConsumersMu.Lock()
	defer transferConsumersMu.Unlock()
	delete(transferConsumers, name)
}

// notifyTransferEventConsumers delivers a completed transfer record to every
// registered consumer.
//
// The registry lock is released before any consumer runs, so a consumer is free
// to register or unregister another without deadlocking, and a slow consumer
// does not block registration.
func notifyTransferEventConsumers(event TransferEvent) {
	transferConsumersMu.RLock()
	if len(transferConsumers) == 0 {
		transferConsumersMu.RUnlock()
		return
	}
	names := make([]string, 0, len(transferConsumers))
	consumers := make([]TransferEventConsumer, 0, len(transferConsumers))
	for name, consumer := range transferConsumers {
		names = append(names, name)
		consumers = append(consumers, consumer)
	}
	transferConsumersMu.RUnlock()

	for i, consumer := range consumers {
		deliverTransferEvent(names[i], consumer, event)
	}
}

// deliverTransferEvent calls one consumer, containing a panic so that a
// misbehaving consumer costs a single record rather than the request.
func deliverTransferEvent(name string, consumer TransferEventConsumer, event TransferEvent) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Transfer-event consumer %q panicked; dropping this record: %v", name, r)
		}
	}()
	consumer(event)
}

// ActiveTransferObserver watches a transfer through its whole life, rather than
// only seeing it once it has finished.
//
// It exists for consumers that maintain a view of what is happening now: a
// record written at BeginActive is visible while the transfer runs, and a row
// that outlives the process is evidence the server stopped mid-transfer. A
// consumer that only cares about completed transfers should register with
// RegisterTransferEventConsumer instead and ignore all of this.
//
// BeginActive returns a key identifying the transfer, which the observer is
// handed back on the later calls. The key is opaque to the caller.
//
// The one-shot emission path calls BeginActive and CompleteActive back to back,
// so an observer must tolerate a transfer that is never updated.
type ActiveTransferObserver interface {
	BeginActive(event TransferEvent) string
	UpdateActive(key string, event TransferEvent)
	CompleteActive(key string, event TransferEvent)
}

var (
	activeObserversMu sync.RWMutex
	activeObservers   = map[string]ActiveTransferObserver{}
)

// RegisterActiveTransferObserver adds an observer of in-flight transfers,
// replacing any registered under the same name.
func RegisterActiveTransferObserver(name string, observer ActiveTransferObserver) {
	if observer == nil {
		return
	}
	activeObserversMu.Lock()
	defer activeObserversMu.Unlock()
	activeObservers[name] = observer
}

// UnregisterActiveTransferObserver removes an observer.
func UnregisterActiveTransferObserver(name string) {
	activeObserversMu.Lock()
	defer activeObserversMu.Unlock()
	delete(activeObservers, name)
}

// snapshotActiveObservers copies the registry so observers run without the lock
// held, matching how consumers are dispatched.
func snapshotActiveObservers() (names []string, observers []ActiveTransferObserver) {
	activeObserversMu.RLock()
	defer activeObserversMu.RUnlock()
	for name, observer := range activeObservers {
		names = append(names, name)
		observers = append(observers, observer)
	}
	return names, observers
}

// beginActiveTransfer notifies every observer that a transfer has started and
// returns the key each one issued, keyed by observer name.
func beginActiveTransfer(event TransferEvent) map[string]string {
	names, observers := snapshotActiveObservers()
	if len(observers) == 0 {
		return nil
	}
	keys := make(map[string]string, len(observers))
	for i, observer := range observers {
		func() {
			defer containObserverPanic(names[i], "begin")
			keys[names[i]] = observer.BeginActive(event)
		}()
	}
	return keys
}

// updateActiveTransfer reports progress on a transfer already begun.
func updateActiveTransfer(keys map[string]string, event TransferEvent) {
	if len(keys) == 0 {
		return
	}
	names, observers := snapshotActiveObservers()
	for i, observer := range observers {
		key, ok := keys[names[i]]
		if !ok {
			continue // registered after this transfer began
		}
		func() {
			defer containObserverPanic(names[i], "update")
			observer.UpdateActive(key, event)
		}()
	}
}

// completeActiveTransfer reports that a transfer has finished.
func completeActiveTransfer(keys map[string]string, event TransferEvent) {
	if len(keys) == 0 {
		return
	}
	names, observers := snapshotActiveObservers()
	for i, observer := range observers {
		key, ok := keys[names[i]]
		if !ok {
			continue
		}
		func() {
			defer containObserverPanic(names[i], "complete")
			observer.CompleteActive(key, event)
		}()
	}
}

// containObserverPanic keeps a misbehaving observer from unwinding into the
// transfer that triggered it, on the same reasoning as deliverTransferEvent.
func containObserverPanic(name, phase string) {
	if r := recover(); r != nil {
		log.Errorf("Active-transfer observer %q panicked during %s: %v", name, phase, r)
	}
}
