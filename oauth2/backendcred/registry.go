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

package backendcred

import (
	"context"
	"sort"
	"sync"

	"github.com/pkg/errors"
)

// TokenSource is what a storage backend needs from a credential: a bearer
// token for the next request.  *Manager implements it, as does FileTokenSource
// for the administrator-maintained token file.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Registry holds a process's backend credentials so that the admin API can
// find the managers that the storage backends were built with.
type Registry struct {
	mu       sync.RWMutex
	managers map[string]*Manager
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{managers: map[string]*Manager{}}
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide registry.
func Default() *Registry { return defaultRegistry }

// ResetDefaultForTest empties the process-wide registry.
func ResetDefaultForTest() { defaultRegistry = NewRegistry() }

// Add registers m.  IDs are unique per process.
func (r *Registry) Add(m *Manager) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.managers[m.ID()]; ok {
		return errors.Errorf("backend credential %s is already registered", m.ID())
	}
	r.managers[m.ID()] = m
	return nil
}

// Get returns the manager with the given ID, or nil.
func (r *Registry) Get(id string) *Manager {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.managers[id]
}

// List returns the managers belonging to owner, ordered by ID.
func (r *Registry) List(owner string) []*Manager {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Manager, 0, len(r.managers))
	for _, m := range r.managers {
		if m.Owner() == owner {
			result = append(result, m)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID() < result[j].ID() })
	return result
}
