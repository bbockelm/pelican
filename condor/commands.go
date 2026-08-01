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
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	htcondorconfig "github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// commandServer builds the daemon's CEDAR command port and the listener it
// serves on.
//
// This is what makes Pelican addressable as a daemon rather than merely
// supervised as a process. With it, condor_ping, condor_off -daemon pelican and
// condor_reconfig -daemon pelican reach this daemon directly. It is separate
// from, and additional to, the HTTPS port clients use: two protocols, two
// audiences.
//
// Authorization comes from the pool's own security configuration, so the
// commands are gated exactly as on a C++ daemon -- DC_NOP at ALLOW, reconfigure
// and shutdown at ADMINISTRATOR.
//
// The listener is whatever the framework can obtain: the socket condor_master
// pre-created and passed down when the daemon is in DC_DAEMON_LIST, a
// self-registered shared-port endpoint otherwise, and failing both the loopback
// fallback below. Loopback on purpose -- a command port no supervisor arranged
// should not be reachable off-host.
func commandServer(d *daemon.Daemon) (*cedarserver.Server, net.Listener, error) {
	sec, err := htcondor.GetServerSecurityConfig(d.Config(), commands.DC_NOP, "DEFAULT")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build the command port's security configuration")
	}

	srv := cedarserver.New(sec)
	d.RegisterDefaultCommands(srv)

	ln, err := d.Listener(func() (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain the command-port listener")
	}

	log.Infof("Pelican command port listening on %s (inherited=%t)",
		ln.Addr().String(), d.AdoptedInheritedListener())
	return srv, ln, nil
}

// onReconfigure runs when condor_reconfig reaches the daemon, whether as the
// master's SIGHUP or a directly-targeted DC_RECONFIG.
//
// The framework has already reloaded the HTCondor configuration by this point.
// Reapply then feeds the changes into Pelican's own hot-reload mechanism, so a
// parameter Pelican marks runtime-configurable takes effect and the modules
// watching it are notified. Anything else is reported by name rather than
// applied: a daemon that took half a configuration would match neither the old
// state nor the new one, and the operator needs to know a restart is pending.
//
// Credentials are flushed unconditionally: they genuinely can be reloaded, and
// rotating one is the usual reason an HTCondor operator reaches for
// condor_reconfig in the first place.
func onReconfigure(cfg *htcondorconfig.Config) {
	flushCredentials()

	applied, deferred, err := Reapply(cfg)
	if err != nil {
		log.WithError(err).Error("Failed to apply the reloaded HTCondor configuration")
		return
	}

	switch {
	case len(applied) > 0:
		log.Infof("Received condor_reconfig: applied %d changed parameter(s): %s",
			len(applied), strings.Join(applied, ", "))
	default:
		log.Info("Received condor_reconfig: no runtime-configurable parameter changed")
	}
	if len(deferred) > 0 {
		// Named rather than counted: an operator who changed one of these needs
		// to know which, or they will assume the reconfigure took effect.
		log.Warnf("These parameters changed but cannot be applied without restarting the daemon: %s",
			strings.Join(deferred, ", "))
	}
}

// serveCommands answers command-port requests until ctx is cancelled.
func serveCommands(ctx context.Context, srv *cedarserver.Server, ln net.Listener) {
	if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
		log.WithError(err).Error("Pelican command port stopped serving")
	}
}

// addressFilePath resolves <SUBSYS>_ADDRESS_FILE, falling back to HTCondor's
// convention of $(LOG)/.<subsys>_address so the daemon is locatable even when
// the pool does not name the file explicitly.
func addressFilePath(d *daemon.Daemon) string {
	if path := knobString(d.Config(), Subsys+"_ADDRESS_FILE"); path != "" {
		return path
	}
	logDir := knobString(d.Config(), "LOG")
	if logDir == "" {
		return ""
	}
	return filepath.Join(logDir, "."+strings.ToLower(Subsys)+"_address")
}

// writeAddressFile publishes where the command port can be reached.
//
// HTCondor's tools locate a daemon either through the collector or through its
// address file, and PELICAN is not one of the subsystems the tools know how to
// resolve by name -- so without this, `condor_ping -addr` has nothing to be
// given and the command port is reachable in principle but not in practice.
// C++ daemons write one; the Go framework reads them but does not write one, so
// Pelican writes its own.
//
// The file is removed on shutdown, so a stale address does not outlive the
// daemon and send a tool to a port nothing is listening on.
func writeAddressFile(d *daemon.Daemon, ln net.Listener) (cleanup func(), err error) {
	path := addressFilePath(d)
	if path == "" {
		return func() {}, nil
	}

	// Prefer the address a peer can actually dial. Behind shared port that is the
	// shared-port server's endpoint plus this daemon's socket name, which is not
	// the same as the listener's own address.
	addr, ok := d.AdvertisedSinful()
	if !ok || addr == "" {
		addr = ln.Addr().String()
	}
	if !strings.HasPrefix(addr, "<") {
		addr = "<" + addr + ">"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, errors.Wrapf(err, "failed to create the directory for %s", path)
	}
	// Written and renamed so a tool never reads a half-written address.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(addr+"\n"), 0o644); err != nil {
		return nil, errors.Wrapf(err, "failed to write %s", path)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, errors.Wrapf(err, "failed to publish %s", path)
	}

	log.Infof("Published the command-port address %s to %s", addr, path)
	return func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Warnf("Failed to remove %s", path)
		}
	}, nil
}
