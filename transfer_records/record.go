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

// Package transfer_records keeps a local, queryable history of the transfers a
// Pelican server has served, as ClassAds in an embedded HTCondor database.
//
// The store is the system of record on the node. A central monitoring service
// collects from it by subscribing to a change feed; nothing in the serving path
// ever waits on that service, and it may be absent for days without affecting
// the server. See docs/transfer-records-design.md.
package transfer_records

import (
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/pelicanplatform/pelican/metrics"
)

// Attribute names for a transfer record. They are exported because a collector
// binds to them: renaming one is a wire change, not a refactor.
const (
	AttrTransferKey   = "TransferKey"
	AttrPath          = "TransferPath"
	AttrReadBytes     = "ReadBytes"
	AttrWriteBytes    = "WriteBytes"
	AttrReadOps       = "ReadOps"
	AttrWriteOps      = "WriteOps"
	AttrClientIP      = "ClientIP"
	AttrUserDN        = "UserDN"
	AttrRole          = "Role"
	AttrAuthProtocol  = "AuthProtocol"
	AttrIssuer        = "Issuer"
	AttrProject       = "Project"
	AttrUserAgent     = "UserAgent"
	AttrStartDate     = "StartDate"
	AttrDurationSecs  = "DurationSeconds"
	AttrServerName    = "PelicanServerName"
	AttrServerType    = "PelicanServerType"
	AttrServerVersion = "PelicanVersion"
	AttrFederation    = "PelicanFederation"
	AttrStatus        = "TransferStatus"

	// AttrCompletionDate is when the transfer finished, in unix seconds. It is
	// the archive's zone-mapped attribute, which makes "everything since T" --
	// the query a collector issues -- prune whole segments rather than scan. It
	// is deliberately named as htcondordb's history table names it, so the same
	// tooling and the same retention-by-age rule apply unchanged.
	AttrCompletionDate = "CompletionDate"
)

// Transfer status values.
const (
	// StatusActive marks a transfer still running. Records with this status live
	// in the in-progress table, never the archive.
	StatusActive = "active"
	// StatusCompleted marks a transfer that finished normally.
	StatusCompleted = "completed"
	// StatusAbandoned marks a transfer that was running when the server stopped.
	// It is what an in-progress row becomes on restart: the server cannot know
	// whether the transfer finished, and saying so is better than either
	// discarding the record or implying success.
	StatusAbandoned = "abandoned"
)

// ServerIdentity describes the server a record came from. It is stamped onto
// every record so that a record is interpretable on its own, without a join
// against whatever the collector happens to know about its sources.
type ServerIdentity struct {
	Name       string
	ServerType string
	Version    string
	Federation string
}

// recordFromEvent projects a completed transfer into a ClassAd.
//
// The projection is field-for-field rather than clever: a collector should be
// able to read the ad without consulting Pelican's source. Empty and zero values
// are omitted so that a record carries only what is actually known -- an absent
// attribute is honest, whereas an empty string implies the field was measured
// and found blank.
func recordFromEvent(event metrics.TransferEvent, id ServerIdentity, status string, key string) *classad.ClassAd {
	ad := classad.New()

	ad.InsertAttrString(AttrTransferKey, key)
	ad.InsertAttrString(AttrStatus, status)
	ad.InsertAttrString(AttrPath, event.Path)

	insertNonZero(ad, AttrReadBytes, event.ReadBytes)
	insertNonZero(ad, AttrWriteBytes, event.WriteBytes)
	insertNonZero(ad, AttrReadOps, int64(event.ReadOps))
	insertNonZero(ad, AttrWriteOps, int64(event.WriteOps))

	insertNonEmpty(ad, AttrClientIP, event.ClientIP)
	insertNonEmpty(ad, AttrUserDN, event.UserDN)
	insertNonEmpty(ad, AttrRole, event.Role)
	insertNonEmpty(ad, AttrAuthProtocol, event.AuthProtocol)
	insertNonEmpty(ad, AttrIssuer, event.Issuer)
	insertNonEmpty(ad, AttrProject, event.Project)
	insertNonEmpty(ad, AttrUserAgent, event.UserAgent)

	if !event.StartTime.IsZero() {
		ad.InsertAttr(AttrStartDate, event.StartTime.Unix())
	}
	end := event.EndTime
	if end.IsZero() {
		end = time.Now()
	}
	ad.InsertAttr(AttrCompletionDate, end.Unix())
	if !event.StartTime.IsZero() && end.After(event.StartTime) {
		// Float rather than integer seconds: most cache hits complete in well under
		// a second, and truncating would record every one of them as zero.
		ad.InsertAttrFloat(AttrDurationSecs, end.Sub(event.StartTime).Seconds())
	}

	insertNonEmpty(ad, AttrServerName, id.Name)
	insertNonEmpty(ad, AttrServerType, id.ServerType)
	insertNonEmpty(ad, AttrServerVersion, id.Version)
	insertNonEmpty(ad, AttrFederation, id.Federation)

	return ad
}

func insertNonEmpty(ad *classad.ClassAd, attr, value string) {
	if value != "" {
		ad.InsertAttrString(attr, value)
	}
}

func insertNonZero(ad *classad.ClassAd, attr string, value int64) {
	if value != 0 {
		ad.InsertAttr(attr, value)
	}
}
