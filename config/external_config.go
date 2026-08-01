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

package config

import (
	"sync/atomic"

	"github.com/spf13/viper"
)

// ExternalConfigProvider contributes configuration from a source outside
// Pelican's own files and environment variables. It is handed the viper instance
// being initialized and merges whatever it has to offer.
//
// A provider should use viper's config layer (MergeConfigMap) rather than Set,
// so that its values layer over config files while environment variables still
// override them -- the precedence a config file has, which is what an operator
// expects of a second configuration source. Using Set would make the provider
// unconditionally authoritative, including over the environment.
type ExternalConfigProvider func(v *viper.Viper) error

// externalConfigProvider holds the registered provider, if any.
var externalConfigProvider atomic.Pointer[ExternalConfigProvider]

// RegisterExternalConfigProvider installs a provider consulted during
// configuration initialization, replacing any previous one.
//
// It must be called before configuration is loaded -- in practice from the
// process's entry point, before the command runs. Registering later has no
// effect on a configuration that has already been read.
//
// This exists so a deployment mode can draw configuration from its environment's
// own system (HTCondor's configuration language, for one) without every such
// mode needing a hook of its own inside the config package, and without the
// config package taking a dependency on any of them.
func RegisterExternalConfigProvider(provider ExternalConfigProvider) {
	if provider == nil {
		externalConfigProvider.Store(nil)
		return
	}
	externalConfigProvider.Store(&provider)
}
