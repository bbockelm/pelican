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

package server_utils

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

// PrepareTokenDir creates dir (with any missing parents) and gives it to
// uid:gid with mode 0750.
//
// It is the directory half of handing an OAuth access token to the XRootD
// daemon: the owner (the pelican process) replaces token files in it, the
// group (the daemon's) reads them, and nobody else can list or read them.
func PrepareTokenDir(dir string, uid, gid int) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return errors.Wrapf(err, "failed to create token directory %s", dir)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return errors.Wrapf(err, "unable to change the ownership of %s to uid %d and gid %d", dir, uid, gid)
	}
	if err := os.Chmod(dir, 0750); err != nil {
		return errors.Wrapf(err, "unable to change the permissions of %s", dir)
	}
	return nil
}

// WriteDaemonTokenFile atomically replaces tokenPath with token, readable by
// the XRootD daemon user.
//
// XRootD's HTTP storage plugins re-read their token file every few seconds,
// so replacing the file is how a refreshed access token reaches a running
// daemon.  The replacement goes through a temporary file in the same
// directory and a rename, so the daemon never reads a half-written token.
// The directory is expected to have been set up by PrepareTokenDir.
func WriteDaemonTokenFile(tokenPath, token string) error {
	uid, err := config.GetDaemonUID()
	if err != nil {
		return errors.Wrap(err, "failed to persist access token: failed to get the daemon uid")
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return errors.Wrap(err, "failed to persist access token: failed to get the daemon gid")
	}

	dir, base := filepath.Split(tokenPath)
	tmp, err := os.CreateTemp(dir, base)
	if err != nil {
		return errors.Wrapf(err, "failed to persist access token: unable to create a temporary file in %s", dir)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chown(uid, gid); err != nil {
		return errors.Wrapf(err, "unable to change the ownership of access token file %s to the daemon user", tmpName)
	}
	if _, err := tmp.Write([]byte(token + "\n")); err != nil {
		return errors.Wrapf(err, "failed to persist access token: unable to write %s", tmpName)
	}
	if err := tmp.Sync(); err != nil {
		return errors.Wrapf(err, "failed to persist access token: unable to flush %s to disk", tmpName)
	}
	if err := os.Rename(tmpName, tokenPath); err != nil {
		return errors.Wrapf(err, "failed to persist access token: unable to rename %s to %s", tmpName, tokenPath)
	}
	committed = true
	return nil
}
