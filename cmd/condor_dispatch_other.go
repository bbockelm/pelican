//go:build (client || server) && (!server || windows)

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

// dispatchCondorDaemon never handles anything in a client-only build, or on
// Windows where running under condor_master is unsupported.
//
// The build constraint mirrors main.go's (client || server) so that this file
// exists exactly where the CLI entry point does -- and no wider, since a stray
// main package with no main function fails to build.
func dispatchCondorDaemon() (bool, error) { return false, nil }
