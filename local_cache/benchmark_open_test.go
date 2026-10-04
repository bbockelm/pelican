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
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// The benchmarks in benchmark_test.go run with the descriptor cache on, as
// production does, so they mostly do not open files.  These two measure the
// paths that always touch the filesystem by name -- opening an object with
// the descriptor cache off, and creating one -- which is where resolving
// paths through an os.Root (one openat per path component) shows up.

// BenchmarkDiskReadUncachedOpen reads a small disk object with the descriptor
// cache disabled, so every iteration opens the file.
func BenchmarkDiskReadUncachedOpen(b *testing.B) {
	env := newBenchEnv(b)
	require.NoError(b, param.LocalCache_FDCacheSize.Set(0))
	// The manager reads the setting when it is built.
	env.storage.fdCacheMaxSize = 0

	const size = 8 * 1024 // just over the inline threshold
	instanceHash := storeDiskObject(b, env, "uncached-open", size)

	b.SetBytes(size)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reader, err := env.storage.NewObjectReader(instanceHash)
		if err != nil {
			b.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, reader)
		reader.Close()
		if n != size {
			b.Fatalf("short read: %d", n)
		}
	}
}

// BenchmarkDiskObjectCreate creates a new disk-backed object per iteration
// (file creation, pre-allocation and its metadata).
func BenchmarkDiskObjectCreate(b *testing.B) {
	env := newBenchEnv(b)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("create-%d", i)
		objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
		instanceHash := env.db.InstanceHash("etag", objectHash)
		if _, err := env.storage.InitDiskStorage(context.Background(), instanceHash, 8*1024, StorageIDFirstDisk, 1); err != nil {
			b.Fatal(err)
		}
	}
}
