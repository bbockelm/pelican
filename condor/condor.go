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

// Package condor runs pelican-server as a daemon supervised by condor_master.
//
// The daemon binds its own port rather than adopting the pool's shared-port
// endpoint, and it is otherwise an ordinary Pelican server: the modules, the web
// engine, and the HTTPS surface are the same ones the standalone daemon runs.
// What changes is who owns the process lifecycle -- condor_master starts it,
// learns when it is ready, monitors it, and tells it when to reconfigure or
// stop.
//
// The package covers mode detection, the daemon bootstrap, translating the
// pool's configuration into Pelican's, reading root-owned pool credentials
// after dropping privilege, the CEDAR command port, and collector
// advertisement. See docs/condor-daemon-design.md.
package condor

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"

	htcondorconfig "github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Subsys is the HTCondor subsystem name for a Pelican daemon. It selects the
// per-daemon configuration knobs condor_master and the config language use for
// this daemon -- PELICAN_LOG, MAX_PELICAN_LOG, PELICAN_DEBUG, PELICAN_ADDRESS_FILE
// -- and names the daemon in the master's DAEMON_LIST.
const Subsys = "PELICAN"

// UnderMaster reports whether this process was started by condor_master.
//
// The probe is environmental (condor_master passes CONDOR_INHERIT to its
// children), so it is answerable before any configuration is loaded -- which
// matters, because the answer selects which configuration system loads.
func UnderMaster() bool {
	return daemon.UnderCondorMaster()
}

// Options configures Serve.
type Options struct {
	// Modules is the set of Pelican server modules to run.
	Modules server_structs.ServerType

	// ListenAddr overrides the address the daemon binds. When empty the address
	// is taken from Server.WebHost and Server.WebPort, as in standalone mode.
	ListenAddr string
}

// Serve runs Pelican's server modules as an HTCondor daemon and blocks until the
// daemon is told to stop.
//
// The daemon framework owns the process lifecycle: it loads the HTCondor
// configuration, drops privileges to the condor account, tells the master when
// initialization has finished (DC_SET_READY), runs the keepalive heartbeat
// (DC_CHILDALIVE), notices if the master dies, and translates SIGTERM into a
// graceful shutdown and SIGHUP into a reconfigure. Pelican's own signal handling
// is therefore switched off; see launchers.WithoutSignalHandling for why the two
// cannot coexist.
//
// Serve returns nil on an orderly shutdown.
func Serve(ctx context.Context, opts Options) error {
	dcArgs := ParseDaemonCoreArgs(os.Args)

	// Build the configuration ourselves rather than letting the framework do it,
	// so the subsystem and local name scope every lookup. The framework's own
	// default calls config.New() with neither, which would resolve knobs at the
	// bare name and quietly ignore the per-instance settings that are the whole
	// reason -local-name exists.
	cfg, err := htcondorconfig.NewWithOptions(htcondorconfig.ConfigOptions{
		Subsystem: Subsys,
		LocalName: dcArgs.LocalName,
	})
	if err != nil {
		return errors.Wrap(err, "failed to read the HTCondor configuration")
	}

	d, err := daemon.New(daemon.Options{
		Subsys:    Subsys,
		LocalName: dcArgs.LocalName,
		Config:    cfg,
	})
	if err != nil {
		return errors.Wrap(err, "failed to initialize the HTCondor daemon framework")
	}
	if dcArgs.LocalName != "" {
		log.Infof("Running as the %q instance of %s", dcArgs.LocalName, Subsys)
	}

	log.Infof("Starting Pelican under condor_master (subsystem %s, under_master=%t)", Subsys, d.UnderMaster())

	if opts.Modules == 0 {
		modules, err := modulesFromConfig(d)
		if err != nil {
			return err
		}
		opts.Modules = modules
	}
	if err := applyConfigFileKnob(d); err != nil {
		return err
	}

	d.OnReconfig(onReconfigure)

	// Present the pool's SSL host credential on the HTTPS port, read with
	// privilege. Registered before the modules launch so both the initial load
	// and the periodic reload go through it.
	if err := useCondorTLSCredential(d); err != nil {
		return err
	}

	cmdSrv, cmdLn, err := commandServer(d)
	if err != nil {
		return err
	}

	// Contribute the pool's configuration to Pelican's. This registers a provider
	// rather than applying anything now, because Pelican's configuration has not
	// been loaded yet -- see §4.1 of the design; the provider runs from inside
	// that load, once the config files have been merged.
	RegisterConfigProvider(d.Config(), opts.Modules)

	removeAddressFile, err := writeAddressFile(d, cmdLn)
	if err != nil {
		_ = cmdLn.Close()
		return err
	}
	defer removeAddressFile()

	ln, err := listen(d, opts)
	if err != nil {
		_ = cmdLn.Close()
		return err
	}

	// Pelican's own configuration has not been read yet -- InitServer is what
	// loads it, and that happens inside LaunchModules below. Zeroing the web port
	// is therefore both possible and correct here: in this mode the port comes
	// from HTCondor configuration (see listen), and a zero port is what makes
	// LaunchModules adopt our socket's address into Server.WebPort,
	// Server.ExternalWebUrl and the URLs derived from them.
	if err := param.Server_WebPort.Set(0); err != nil {
		return errors.Wrap(err, "failed to defer the web port to the listener")
	}

	// The daemon framework has already dropped to the condor account, and did so
	// reversibly (HTCondor's set_priv model) precisely so the daemon can still
	// read root-owned pool credentials afterwards. Pelican's own drop is a
	// permanent setuid to a different account; running it on top would both
	// target the wrong user and destroy the re-elevation the credential path
	// depends on. Disable it -- these are two answers to the same question, and
	// under condor_master the framework's is the operative one.
	//
	// This is an override rather than a validation error because config.isRootExec
	// is latched during package initialization, before the framework's drop, so
	// Pelican still believes it is running as root at the point it would decide.
	if err := param.Server_DropPrivileges.Set(false); err != nil {
		return errors.Wrap(err, "failed to disable Pelican's privilege drop")
	}
	log.Debug("HTCondor mode manages the privilege drop; Server.DropPrivileges is not consulted")

	// The daemon framework drives the served function with a context it cancels
	// on shutdown. LaunchModules starts the modules in the background and returns,
	// so the serve function blocks until that context is cancelled; cancellation
	// is what performs Pelican's graceful teardown once signals belong to the
	// framework.
	// The listener the framework drives is the command port; Pelican's HTTPS
	// listener is the one bound above and captured here. Keeping them apart is
	// the point: the framework owns the daemon's command socket while Pelican
	// serves data on a port of its own.
	serve := func(ctx context.Context, cmdLn net.Listener) error {
		_, shutdownCancel, err := launchers.LaunchModules(ctx, opts.Modules,
			launchers.WithListener(ln),
			launchers.WithoutSignalHandling(),
		)
		if err != nil {
			// Log as well as return: on the termination path the framework
			// reports an orderly shutdown regardless of what the served function
			// returned, so an error raised while starting up would otherwise
			// leave no trace of why the daemon never came up.
			log.WithError(err).Error("Failed to launch Pelican modules")
			return errors.Wrap(err, "failed to launch Pelican modules")
		}
		defer shutdownCancel()

		log.Info("Pelican modules are running under condor_master")

		// Advertise only once the modules are up, so the first ad describes a
		// server that is actually serving rather than one still starting. The
		// loop returns when ctx is cancelled, having invalidated the ad.
		advertiseDone := make(chan struct{})
		go func() {
			defer close(advertiseDone)
			advertise(ctx, d, opts.Modules)
		}()

		// Answer command-port requests until shutdown. This blocks, which keeps
		// the served function alive for the daemon's lifetime.
		serveCommands(ctx, cmdSrv, cmdLn)

		<-advertiseDone
		log.Info("Shutdown requested; stopping Pelican modules")
		return nil
	}

	if err := d.Serve(ctx, cmdLn, serve); err != nil {
		return errors.Wrap(err, "the Pelican daemon exited with an error")
	}
	log.Info("Pelican daemon has shut down")
	return nil
}

// modulesFromConfig reads which Pelican modules to run from the pool
// configuration.
//
// In HTCondor mode the module set is configuration, not a command-line flag:
// the daemon is started by condor_master, whose argv belongs to DaemonCore
// rather than to Pelican (see §3.3 of the design).
//
//	PELICAN_SERVER_MODULES = origin, cache
//
// The knob is spelled as the translation layer spells Server.Modules, so an
// operator learns one rule rather than a special case.
func modulesFromConfig(d *daemon.Daemon) (server_structs.ServerType, error) {
	knob := ParamKnob(param.Server_Modules.GetName())
	names := knobList(d.Config(), knob)
	if len(names) == 0 {
		return 0, errors.Errorf(
			"no Pelican modules are enabled; set %s in the HTCondor configuration (for example %s = origin)",
			knob, knob)
	}
	modules := server_structs.NewServerType()
	for _, name := range names {
		if !modules.SetString(name) {
			return 0, errors.Errorf("%s names an unknown module %q", knob, name)
		}
	}
	return modules, nil
}

// applyConfigFileKnob lets the pool configuration point at a Pelican YAML file,
// standing in for the --config flag that HTCondor mode cannot use.
//
// Most settings are better expressed as PELICAN_* knobs, but a few -- the
// structured parameters HTCondor mode does not translate (§4.3) -- have no
// knob form, and an operator needs some way to supply them.
func applyConfigFileKnob(d *daemon.Daemon) error {
	path := knobString(d.Config(), "PELICAN_CONFIG_FILE")
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return errors.Wrapf(err, "PELICAN_CONFIG_FILE names %s, which cannot be read", path)
	}
	// "config" is the viper key Pelican's own --config flag binds to, so setting
	// it here reaches the same code that would have handled the flag.
	viper.Set("config", path)
	log.Infof("Reading Pelican configuration from %s", path)
	return nil
}

// listen binds the daemon's HTTPS listener.
//
// Unlike a CEDAR daemon, Pelican does not adopt the inherited shared-port
// endpoint: it speaks HTTPS to clients that know nothing about the shared-port
// handshake, so it needs a directly-dialable port of its own.
//
// The address comes from HTCondor configuration rather than Pelican's, because
// Pelican's configuration is not loaded until InitServer runs inside
// LaunchModules -- reading param.Server_WebPort here would see an unset value
// and silently bind the wrong port. Taking it from the pool configuration is
// also the direction the full design goes: in this mode HTCondor configuration
// is authoritative.
//
//	PELICAN_PORT          the TCP port to serve on; 0 (the default) picks an
//	                      ephemeral port, which the rest of the configuration
//	                      then adopts.
//	PELICAN_BIND_ADDRESS  the interface to bind; empty (the default) binds all.
func listen(d *daemon.Daemon, opts Options) (net.Listener, error) {
	addr := opts.ListenAddr
	if addr == "" {
		cfg := d.Config()
		host := ""
		port := 0
		if cfg != nil {
			if v, ok := cfg.Get("PELICAN_BIND_ADDRESS"); ok {
				host = strings.TrimSpace(v)
			}
			if v, ok := cfg.Get("PELICAN_PORT"); ok {
				p, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil {
					return nil, errors.Wrapf(err, "PELICAN_PORT is not a number: %q", v)
				}
				port = p
			}
		}
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to listen on %s", addr)
	}
	log.Infof("Pelican daemon listening on %s", ln.Addr().String())
	return ln, nil
}
