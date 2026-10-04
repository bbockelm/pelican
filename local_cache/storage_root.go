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
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Every filesystem operation on a cache object goes through an *os.Root
// opened on its storage directory's objects/ subdirectory when the
// StorageManager starts, rather than through an absolute path.
//
// The paths are built from instance hashes, which are validated (see
// InstanceHash), so they cannot name anything outside the directory today.
// The root makes that a property of the filesystem layer instead of an
// argument about every caller: a relative path that tried to climb out, or a
// symlink planted inside the tree, is refused by the kernel-facing code
// rather than followed.
//
// Two operational consequences, both documented under LocalCache.StorageDirs:
//
//   - Symlinks inside a storage directory are unsupported.  The configured
//     directory and its objects/ may themselves be symlinks (the root is
//     opened through them), but beneath that os.Root refuses any symlink
//     that is absolute or leads out of the tree -- including absolute ones
//     that point back inside it.  Spreading one directory over several
//     disks by symlinking its aa/ fan-out directories therefore does not
//     work; list the disks as separate StorageDirs.  checkStorageSymlinks
//     catches the fan-out case at startup, with a clear error, rather than
//     leaving every read beneath it to fail.
//   - The root pins each directory for the life of the process.  A storage
//     directory that is renamed, deleted and recreated, or mounted over
//     while the cache runs keeps receiving writes in the old directory --
//     invisible at the path, its space not freed until restart -- and a
//     cache started before its disk was mounted keeps writing to the
//     mount point underneath.  Replacing or remounting a storage directory
//     needs a restart.
//
// The cost is that os.Root resolves each path component with its own
// openat(O_NOFOLLOW) (Go has no openat2 fast path yet), so opening
// aa/bb/<hash> takes a handful of syscalls instead of one.  Opens are off
// the hot path: the StorageManager caches open descriptors (openFiles), and
// reads and writes use ReadAt/WriteAt on those.

// storageRoot is one storage directory as the StorageManager holds it.
type storageRoot struct {
	// root confines operations to the objects directory.  It is nil only
	// for a read-only manager whose directory could not be opened, in
	// which case err says why.
	root *os.Root
	err  error
}

// openStorageRoots opens a root on each objects directory and checks it with
// checkStorageSymlinks.  A writable
// manager creates the directories (objects are created under them) and fails
// if any cannot be opened.  A read-only manager -- used by offline tools that
// may be pointed at a store whose directories are not all mounted -- records
// the failure instead, and operations on that directory report it.
func openStorageRoots(objDirs map[StorageID]string, create bool) (map[StorageID]storageRoot, error) {
	roots := make(map[StorageID]storageRoot, len(objDirs))
	for id, dir := range objDirs {
		if create {
			if err := os.MkdirAll(dir, 0750); err != nil {
				closeStorageRoots(roots)
				return nil, errors.Wrapf(err, "failed to create storage directory %s", dir)
			}
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			if create {
				closeStorageRoots(roots)
				return nil, errors.Wrapf(err, "failed to open storage directory %s", dir)
			}
			roots[id] = storageRoot{err: err}
			continue
		}
		roots[id] = storageRoot{root: root}
		if err := checkStorageSymlinks(root, dir); err != nil {
			if create {
				closeStorageRoots(roots)
				return nil, err
			}
			log.Warn(err)
		}
	}
	return roots, nil
}

// checkStorageSymlinks looks for symlinks os.Root will not follow in the
// fan-out directories (aa/ and aa/bb/) of an objects directory.  Every object
// beneath such a link would fail to open, so a writable manager refuses to
// start rather than serve errors; it is the one arrangement an operator
// might plausibly have built on purpose (spreading a directory over disks).
// Object files themselves are not checked: there are too many, and a cache
// never creates a link.  A symlink the root can follow (relative, staying
// inside the tree) is accepted.
//
// It costs one directory listing per fan-out directory present -- at most
// 257 -- and a stat per symlink found.
func checkStorageSymlinks(root *os.Root, dir string) error {
	fsys := root.FS()
	check := func(rel string) ([]fs.DirEntry, error) {
		entries, err := fs.ReadDir(fsys, rel)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list storage directory %s", filepath.Join(dir, rel))
		}
		for _, e := range entries {
			if e.Type()&fs.ModeSymlink == 0 {
				continue
			}
			name := path.Join(rel, e.Name())
			if _, err := root.Stat(filepath.FromSlash(name)); err != nil {
				return nil, errors.Errorf("storage directory %s contains the symbolic link %s, which cannot be "+
					"followed (%v): symbolic links inside a storage directory are not supported -- list each "+
					"disk as a separate storage directory instead", dir, filepath.FromSlash(name), err)
			}
		}
		return entries, nil
	}
	top, err := check(".")
	if err != nil {
		return err
	}
	for _, e := range top {
		if !e.IsDir() || len(e.Name()) != 2 {
			continue
		}
		if _, err := check(e.Name()); err != nil {
			return err
		}
	}
	return nil
}

// closeStorageRoots closes every open root.  Files already opened through a
// root stay valid.
func closeStorageRoots(roots map[StorageID]storageRoot) {
	for _, r := range roots {
		if r.root != nil {
			_ = r.root.Close()
		}
	}
}

// errStorageDirNotConfigured is returned for a storage ID with no local
// directory.  It wraps fs.ErrNotExist: an object whose directory is not
// configured is, as far as the caller is concerned, an object whose file is
// missing -- which is what looking it up used to report -- and it is never
// looked for anywhere else.
var errStorageDirNotConfigured = errors.Wrap(fs.ErrNotExist, "storage directory is not configured")

// storageRootFor returns the root for a storage directory.
func (sm *StorageManager) storageRootFor(storageID StorageID) (*os.Root, error) {
	r, ok := sm.roots[storageID]
	if !ok {
		return nil, errors.Wrapf(errStorageDirNotConfigured, "storage ID %d", storageID)
	}
	if r.root == nil {
		return nil, errors.Wrapf(r.err, "storage directory %s is unavailable", sm.dirs[storageID])
	}
	return r.root, nil
}

// chunkRelPath is a chunk file's path relative to its objects directory.
func chunkRelPath(instanceHash InstanceHash, chunkIndex int) string {
	return GetChunkPath(filepath.FromSlash(GetInstanceStoragePath(instanceHash)), chunkIndex)
}

// chunkFilePath is a chunk file's absolute path.  It is for messages and
// for reporting where a file lives; operate on the file through the
// *ChunkFile methods instead.
func (sm *StorageManager) chunkFilePath(storageID StorageID, instanceHash InstanceHash, chunkIndex int) string {
	dir, ok := sm.dirs[storageID]
	if !ok {
		return ""
	}
	return filepath.Join(dir, chunkRelPath(instanceHash, chunkIndex))
}

// openChunkFile opens a chunk file (chunk 0 is the object's base file).  With
// os.O_CREATE in flag, missing parent directories are created.
func (sm *StorageManager) openChunkFile(storageID StorageID, instanceHash InstanceHash, chunkIndex int, flag int) (*os.File, error) {
	root, err := sm.storageRootFor(storageID)
	if err != nil {
		return nil, err
	}
	rel := chunkRelPath(instanceHash, chunkIndex)
	f, err := root.OpenFile(rel, flag, 0600)
	if err == nil || flag&os.O_CREATE == 0 || !errors.Is(err, fs.ErrNotExist) {
		return f, err
	}
	// Create the aa/bb/ parents lazily rather than checking for them up
	// front: they already exist for almost every object.
	if mkErr := root.MkdirAll(filepath.Dir(rel), 0750); mkErr != nil {
		return nil, mkErr
	}
	return root.OpenFile(rel, flag, 0600)
}

// createChunkFile creates (or truncates) a chunk file for writing.
func (sm *StorageManager) createChunkFile(storageID StorageID, instanceHash InstanceHash, chunkIndex int) (*os.File, error) {
	return sm.openChunkFile(storageID, instanceHash, chunkIndex, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
}

// statChunkFile stats a chunk file.
func (sm *StorageManager) statChunkFile(storageID StorageID, instanceHash InstanceHash, chunkIndex int) (fs.FileInfo, error) {
	root, err := sm.storageRootFor(storageID)
	if err != nil {
		return nil, err
	}
	return root.Stat(chunkRelPath(instanceHash, chunkIndex))
}

// removeChunkFile removes a chunk file.  A file that is already gone is not
// an error.
func (sm *StorageManager) removeChunkFile(storageID StorageID, instanceHash InstanceHash, chunkIndex int) error {
	root, err := sm.storageRootFor(storageID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return removeInRoot(root, chunkRelPath(instanceHash, chunkIndex))
}

// removeInRoot removes a file under a root, retrying briefly on Windows if the
// file is still held open by an asynchronous eviction callback (ttlcache
// fires OnEviction in a goroutine, so the file descriptor may not be closed
// by the time we attempt the delete).  A file that is already gone is not an
// error.
func removeInRoot(root *os.Root, rel string) error {
	err := root.Remove(rel)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if runtime.GOOS != "windows" {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		time.Sleep(10 * time.Millisecond)
		err = root.Remove(rel)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
	}
	return err
}

// DiskUsage walks every storage directory and totals the files in it.  This
// reads every file's size, so it is expensive.  Entries that cannot be read
// are skipped, as is a directory a read-only manager could not open.
func (sm *StorageManager) DiskUsage() *DiskUsageResult {
	start := time.Now()
	result := &DiskUsageResult{
		Directories: make(map[string]*DirDiskStat),
	}
	for storageID, objectsDir := range sm.dirs {
		ds := &DirDiskStat{
			StorageID: uint8(storageID),
			Path:      objectsDir,
		}
		if root, err := sm.storageRootFor(storageID); err == nil {
			_ = fs.WalkDir(root.FS(), ".", func(_ string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil || d.IsDir() {
					return nil
				}
				if info, err := d.Info(); err == nil {
					ds.FileCount++
					ds.BytesUsed += info.Size()
				}
				return nil
			})
		}
		result.Directories[fmt.Sprintf("storage-%d", storageID)] = ds
		result.TotalBytesOnDisk += ds.BytesUsed
		result.TotalFiles += ds.FileCount
	}
	result.Duration = time.Since(start).String()
	return result
}
