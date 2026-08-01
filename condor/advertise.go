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
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/daemon"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/version"
)

// AdType is the MyType of the ClassAd a Pelican server advertises.
//
// A single ad type covers every module combination, with PelicanServerType
// naming what is actually running. Pelican deliberately allows several modules
// in one process, so one ad per daemon reflects the deployment; a separate ad
// type per module would either misrepresent a combined server or require
// several ads describing the same process.
//
// It is not one of HTCondor's standard types, so updates route through
// UPDATE_AD_GENERIC.
const AdType = "PelicanServer"

// advertise runs the collector advertisement loop until ctx is cancelled.
//
// The daemon framework owns the mechanics -- the update cadence, the monotonic
// sequence number, the common daemon attributes, DAEMON_SHUTDOWN evaluation, and
// invalidating the ad on exit. Pelican only supplies its own attributes. When no
// COLLECTOR_HOST is configured the framework logs once and returns, so this is
// harmless on a pool that does not want the ads.
func advertise(ctx context.Context, d *daemon.Daemon, modules server_structs.ServerType) {
	d.Advertise(ctx, daemon.AdvertiseConfig{
		MyType: AdType,
		Augment: func(ad *classad.ClassAd) {
			augmentAd(ad, modules)
		},
	})
}

// augmentAd adds Pelican's attributes to an ad already seeded with the common
// daemon ones (Name, Machine, MyAddress, CondorVersion, DaemonStartTime, ...).
//
// Attributes are prefixed Pelican* so they cannot collide with HTCondor's own
// namespace in a collector holding ads from every daemon in the pool.
func augmentAd(ad *classad.ClassAd, modules server_structs.ServerType) {
	ad.InsertAttrString("PelicanVersion", version.GetVersion())
	ad.InsertAttrString("PelicanServerType", moduleList(modules))

	if url := param.Server_ExternalWebUrl.GetString(); url != "" {
		ad.InsertAttrString("PelicanExternalWebUrl", url)
	}
	if fed := param.Federation_DiscoveryUrl.GetString(); fed != "" {
		ad.InsertAttrString("PelicanFederation", fed)
	}

	// The overall health rollup Pelican already computes for its own status API,
	// so an operator sees the same verdict from condor_status as from the web UI.
	health := metrics.GetHealthStatus()
	ad.InsertAttrString("PelicanHealthStatus", health.OverallStatus)
}

// moduleList renders the enabled modules as a stable, comma-separated string --
// sorted so that an ad's value does not churn with map iteration order, which
// would otherwise make every update look like a change.
func moduleList(modules server_structs.ServerType) string {
	names := []string{}
	for _, m := range []struct {
		t    server_structs.ServerType
		name string
	}{
		{server_structs.OriginType, "Origin"},
		{server_structs.CacheType, "Cache"},
		{server_structs.DirectorType, "Director"},
		{server_structs.RegistryType, "Registry"},
		{server_structs.BrokerType, "Broker"},
		{server_structs.LocalCacheType, "LocalCache"},
	} {
		if modules.IsEnabled(m.t) {
			names = append(names, m.name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		log.Warn("Advertising a Pelican ad with no enabled modules")
		return ""
	}
	return strings.Join(names, ",")
}
