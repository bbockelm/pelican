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

import "strings"

// DaemonCoreArgs is what Pelican takes from the command line condor_master
// builds for a DaemonCore daemon.
//
// Pelican does not use the command line for its own configuration in this mode
// (see cmd/condor_dispatch_unix.go), but it cannot ignore it either: DaemonCore
// arguments carry information that changes how configuration is read.
type DaemonCoreArgs struct {
	// LocalName is -local-name. It is the important one.
	//
	// HTCondor resolves a knob through the local name before the bare name --
	// <SUBSYS>.<LOCALNAME>.<KEY>, then <LOCALNAME>.<KEY>, then <KEY> -- which is
	// how two instances of the same daemon on one host are configured
	// differently. A daemon that discarded it would silently read the shared
	// values and look like it was working.
	LocalName string

	// Sock is -sock, the shared-port endpoint name the master assigned.
	Sock string
}

// ParseDaemonCoreArgs extracts what Pelican needs from a DaemonCore command
// line, ignoring the rest.
//
// Ignoring the rest is deliberate rather than lazy. The master passes arguments
// that mean nothing here -- the subsystem name, -f, -t, -p and others that vary
// between HTCondor versions -- and a parser that rejected unrecognized
// arguments would turn every such addition into a daemon that refuses to start.
// The failure mode of skipping something is a knob read at the wrong scope; the
// failure mode of being strict is a pool that will not come up after an upgrade.
//
// args should be os.Args, including the program name.
func ParseDaemonCoreArgs(args []string) DaemonCoreArgs {
	var parsed DaemonCoreArgs
	for i := 1; i < len(args); i++ {
		// HTCondor accepts one or two leading dashes interchangeably.
		flag := strings.ToLower(strings.TrimLeft(args[i], "-"))
		value := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch flag {
		case "local-name", "localname":
			// Passed through as written. Scoped lookups are case-insensitive as of
			// golang-htcondor v0.12.4, matching HTCondor, so "-local-name cache_a"
			// finds a CACHE_A.* definition and vice versa. An earlier workaround
			// here upper-cased the name; that fixed one direction and broke the
			// other, since it then missed a lower-case definition.
			parsed.LocalName = value()
		case "sock":
			parsed.Sock = value()
		}
	}
	return parsed
}
