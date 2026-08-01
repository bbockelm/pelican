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
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/condor"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/server_structs"
)

// launchServer starts the given server modules in whichever mode this process
// was started in.
//
// When condor_master launched us, the daemon runs under its supervision: the
// master learns when startup finished, monitors the process, and drives
// reconfigure and shutdown. That mode blocks until the daemon is told to stop.
// Otherwise this is an ordinary standalone launch, which returns as soon as the
// modules are running and leaves the process alive via the errgroup in Execute.
//
// Detection is environmental and needs no configuration, so a host that does not
// run HTCondor behaves exactly as it always has.
func launchServer(cmd *cobra.Command, modules server_structs.ServerType) error {
	if condor.UnderMaster() {
		return condor.Serve(cmd.Context(), condor.Options{Modules: modules})
	}

	_, cancel, err := launchers.LaunchModules(cmd.Context(), modules)
	if err != nil {
		cancel()
	}
	return err
}
