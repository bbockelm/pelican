//go:build server && !windows

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

package main

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/condor"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/logging"
)

// dispatchCondorDaemon runs the daemon directly when condor_master started this
// process, bypassing the command-line interface entirely.
//
// The command line is not Pelican's to parse here. A daemon named in
// DC_DAEMON_LIST is launched with DaemonCore's own arguments -- the subsystem
// name, and -local-name -- which a cobra command tree rejects as an unknown
// command before any Pelican code runs. Filtering those arguments back out
// would mean tracking what condor_master passes across HTCondor versions, to
// arrive at an empty flag set anyway.
//
// So HTCondor mode reads none of it. Everything that would have been a flag is
// configuration: which modules to run, which port to bind, where the Pelican
// configuration file is. That is the right shape regardless -- a supervised
// daemon is configured by its pool, not by a command line nobody types.
//
// Returns handled=false when not under condor_master, leaving the normal CLI
// untouched.
func dispatchCondorDaemon() (handled bool, err error) {
	if !condor.UnderMaster() {
		return false, nil
	}

	// The daemon owns the process, so it also owns the errgroup the server
	// modules run in -- there is no cobra Execute to do it here.
	egrp, egrpCtx := errgroup.WithContext(context.Background())
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	serveErr := condor.Serve(ctx, condor.Options{})

	// Let the modules finish shutting down before reporting. Their errors are
	// secondary to whatever stopped the daemon, so they are logged rather than
	// returned in its place.
	if waitErr := egrp.Wait(); waitErr != nil && serveErr == nil {
		serveErr = waitErr
	}
	logging.FlushLogs(true)
	return true, serveErr
}
