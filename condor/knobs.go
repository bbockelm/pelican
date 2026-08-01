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

package condor

import (
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
)

// A list-of-structures parameter is expressed in HTCondor configuration as a
// knob family:
//
//	<LIST>                  = itemA, itemB     // which items exist
//	<PREFIX>_<ITEM>_<FIELD> = value            // each item's fields
//
// The list knob is authoritative. Items are named rather than numbered so that
// adding, removing, or reordering one does not renumber the others, and so a
// single item's field can be overridden from a drop-in configuration file the
// way HTCondor administrators expect.
//
// The helpers below read the pieces; each parameter's handler knows its own
// knob names and field set (see object_params.go).

// knobString returns a knob's value with surrounding whitespace removed, or ""
// when it is unset or blank.
func knobString(cfg *config.Config, knob string) string {
	if cfg == nil {
		return ""
	}
	v, ok := cfg.Get(knob)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// knobList splits a knob's value on commas or whitespace, the way HTCondor's own
// list-valued knobs (DAEMON_LIST, COLLECTOR_HOST, ...) are written. Empty
// elements are dropped, so trailing separators and line continuations are
// harmless.
func knobList(cfg *config.Config, knob string) []string {
	raw := knobString(cfg, knob)
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	items := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			items = append(items, f)
		}
	}
	if len(items) == 0 {
		return nil
	}
	return items
}

// knobToken normalizes an item name into the form used inside a knob name:
// upper-cased, with anything outside [A-Z0-9_] replaced by an underscore.
//
// This is what lets an operator write a readable item name in the list knob and
// have the per-field knobs follow predictably. Normalizing rather than
// rejecting keeps names like "my-export" usable, at the cost of "my-export" and
// "my_export" colliding -- which is caught as a duplicate rather than silently
// merged.
func knobToken(item string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(item)) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
