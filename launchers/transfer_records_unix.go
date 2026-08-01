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

package launchers

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/transfer_records"
	"github.com/pelicanplatform/pelican/version"
	"github.com/pelicanplatform/pelican/web_ui"
)

// launchTransferRecords starts the local transfer-record store and mounts its
// change feed, when Monitoring.EnableTransferRecords is set.
//
// The store is a consumer of the same completed-transfer events the XRootD
// monitoring shoveler consumes, and is independent of it: either, both, or
// neither may be enabled.
func launchTransferRecords(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, modules server_structs.ServerType) error {
	if !param.Monitoring_EnableTransferRecords.GetBool() {
		return nil
	}

	dir := param.Monitoring_TransferRecordsLocation.GetString()
	if dir == "" {
		return errors.Errorf("%s is enabled but %s is empty",
			param.Monitoring_EnableTransferRecords.GetName(),
			param.Monitoring_TransferRecordsLocation.GetName())
	}

	store, err := transfer_records.Open(transfer_records.Config{
		Dir:      dir,
		MaxBytes: int64(param.Monitoring_TransferRecordsMaxSize.GetInt()),
		Identity: transfer_records.ServerIdentity{
			Name:       param.Server_Hostname.GetString(),
			ServerType: modules.String(),
			Version:    version.GetVersion(),
			Federation: param.Federation_DiscoveryUrl.GetString(),
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to open the transfer-record store")
	}

	// Account for transfers that were running when this server last stopped,
	// before anything new is recorded. Doing it first means a collector sees the
	// abandoned records in the order they occurred rather than interleaved with
	// the current run's.
	if _, err := store.Reconcile(); err != nil {
		// Not fatal: failing to tidy up after a previous crash is a reason to
		// complain, not a reason to refuse to serve data now.
		log.WithError(err).Error("Failed to reconcile transfers left over from a previous run")
	}

	// Registered as an observer rather than a plain consumer: the store tracks a
	// transfer from start to finish, so it archives the record itself at the end.
	// Doing both would archive every transfer twice.
	// Publish the store for components assembled before this point -- the
	// HTCondor command port among them. Cleared on shutdown below.
	transfer_records.SetShared(store)

	metrics.RegisterActiveTransferObserver("transfer_records", store)
	store.RunMaintenance(ctx)
	store.RegisterFeedRoutes(engine.Group("/", web_ui.ServerHeaderMiddleware))

	egrp.Go(func() error {
		<-ctx.Done()
		metrics.UnregisterActiveTransferObserver("transfer_records")
		transfer_records.SetShared(nil)
		if err := store.Close(); err != nil {
			log.WithError(err).Warn("Failed to close the transfer-record store cleanly")
		}
		log.Debug("Transfer-record store has shut down")
		return nil
	})

	log.Infof("Recording transfers to %s (limit %d bytes); change feed at %s",
		dir, param.Monitoring_TransferRecordsMaxSize.GetInt(), transfer_records.FeedRoutePrefix)
	return nil
}
