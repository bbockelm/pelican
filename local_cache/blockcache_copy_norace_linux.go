//go:build linux && !race

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

import "unsafe"

// arenaCopyMode names the strategy in use, for diagnostics/tests.
const arenaCopyMode = "plain"

// In non-race builds the arena payload is copied with a plain memmove for
// speed.  Concurrent with a slot rewrite this is a benign seqlock race: the
// caller's post-copy gen recheck discards any torn read, so a wrong/torn block
// is never returned.  Race-detector builds use the atomic-word variant instead
// (see blockcache_copy_race_linux.go) so -race stays clean.
func arenaLoad(dst []byte, base unsafe.Pointer)  { plainLoadBytes(dst, base) }
func arenaStore(base unsafe.Pointer, src []byte) { plainStoreBytes(base, src) }
