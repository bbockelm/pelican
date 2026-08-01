//go:build windows

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

package launchers

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// launchTransferRecords refuses on Windows rather than silently doing nothing.
// The embedded store relies on memory-mapped segment files, so the feature is
// unavailable here; an operator who enabled it deserves to be told, not to find
// an empty change feed later.
func launchTransferRecords(_ context.Context, _ *gin.Engine, _ *errgroup.Group, _ server_structs.ServerType) error {
	if !param.Monitoring_EnableTransferRecords.GetBool() {
		return nil
	}
	return errors.Errorf("%s is not supported on Windows", param.Monitoring_EnableTransferRecords.GetName())
}
