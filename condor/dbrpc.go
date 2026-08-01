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

	"github.com/PelicanPlatform/classad/dbrpc"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/transfer_records"
)

// DBSessionCommand is the CEDAR command carrying a multiplexed dbrpc session.
//
// The value is htcondordb's, taken from HTCondor's retired TRANSFERD_BASE block
// (74000), which was commented out and marked unused and so collides with
// nothing live. It is duplicated here rather than imported because importing
// htcondordb would pull an entire daemon in for one integer; the comment is the
// link back to the source of truth.
//
//nolint:misspell // TRANSFERD_BASE is HTCondor's identifier, not a misspelling
const DBSessionCommand = 74001

// mountTransferRecordsDB exposes the transfer-record store over dbrpc on the
// daemon's command port, so htcondordb-cli can run SQL against it:
//
//	htcondordb-cli -addr "$(cat $(LOG)/.pelican_address)"
//	> SELECT TransferPath, ReadBytes FROM transfers WHERE Project == "cms" LIMIT 20
//
// Two deliberate restrictions, both narrower than htcondordb's own service.
//
// **DAEMON only.** htcondordb registers the session at READ and escalates per
// connection. Here the records name the object transferred, the address that
// asked for it, and the user who authenticated, so the whole surface is gated at
// the level HTCondor reserves for secret material rather than the one it uses
// for ordinary queries. A pool's READ list is usually far wider than its DAEMON
// list, and this data does not belong to everyone who may run condor_status.
//
// **Read-only, unconditionally.** The store is Pelican's own record of what it
// served; there is no legitimate reason to write to it over CEDAR, and a
// mutation path would be a way to falsify accounting. Private attributes stay
// hidden for the same reason -- a DAEMON peer is trusted to read the records,
// not to be handed anything the store marks secret.
//
// This is a separate access path from the change feed, with separate
// credentials: the feed authenticates a federation token bearing monitoring.raw,
// while this authenticates the pool's own CEDAR identity. That is deliberate --
// the feed serves the federation, this serves the machine's operator -- but it
// does mean two authorization systems reach the same data, and both have to be
// got right.
// The store is resolved per connection rather than captured, because the
// command port is built before the modules launch and therefore before the
// store exists.
func mountTransferRecordsDB(d *daemon.Daemon, srv *cedarserver.Server) {
	srv.Handle(DBSessionCommand, func(ctx context.Context, c *cedarserver.Conn) error {
		store := transfer_records.Shared()
		if store == nil {
			return errors.New("transfer records are not enabled on this server")
		}
		rpc := dbrpc.NewServerCatalog(store.Catalog())

		// Logged per connection at Info: an operator asking "who read the
		// transfer records?" should find the answer without enabling debug.
		log.Infof("Transfer-record SQL session opened by %s from %s", peerUser(c), c.RemoteAddr)

		conn := dbrpc.NewCedarConn(ctx, c.Stream)
		err := rpc.ServeConnOpts(conn, dbrpc.ServeOptions{
			ReadOnly:       true,
			IncludePrivate: false,
		})
		if err != nil {
			log.Debugf("Transfer-record SQL session from %s ended: %v", c.RemoteAddr, err)
		}
		return err
	}, "DAEMON")

	log.Infof("Transfer records queryable over dbrpc on the command port (DAEMON, read-only) when enabled; "+
		"htcondordb-cli -addr \"$(cat %s)\"", addressFilePath(d))
}

// peerUser returns the authenticated identity of a connection, or "unknown".
func peerUser(c *cedarserver.Conn) string {
	if c != nil && c.Negotiation != nil && c.Negotiation.User != "" {
		return c.Negotiation.User
	}
	return "unknown"
}

// installAuthorizer gives the command server the pool's authorization tables.
//
// Without one, CEDAR "advertises only the negotiated command (no authorization
// table applied)" -- the per-command levels passed to Handle are recorded but
// never consulted. Registering the dbrpc session at DAEMON would then be
// decoration: any peer that could authenticate at all could open it.
//
// authz.Policy resolves the ALLOW_/DENY_ tables the same way HTCondor's
// IpVerify does, including the per-subsystem variants, so the daemon enforces
// exactly the policy the pool's configuration describes.
func installAuthorizer(d *daemon.Daemon, srv *cedarserver.Server) error {
	policy, err := authz.NewPolicy(d.Config(), Subsys)
	if err != nil {
		return errors.Wrap(err, "failed to build the command port's authorization policy")
	}
	srv.Authorizer = policy.Authorize
	return nil
}
