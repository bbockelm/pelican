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

package transfer_records

import (
	"context"
	"net/http"
	"time"

	"github.com/PelicanPlatform/classad/changefeed"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// FeedRoutePrefix is where the change feed is mounted. The upstream handler owns
// the paths beneath it (/changefeed/v1/subscribe and /changefeed/v1/ack).
const FeedRoutePrefix = "/api/v1.0/transfer_records"

// contextWithSubscriber stashes the authenticated subscriber identity for the
// upstream handler's Authorizer to read back.
func contextWithSubscriber(parent context.Context, subscriber string) context.Context {
	return context.WithValue(parent, subscriberContextKey{}, subscriber)
}

// subscriberContextKey is where the authenticated subscriber identity is stashed
// between the gin middleware and the upstream handler's Authorizer.
type subscriberContextKey struct{}

// RegisterFeedRoutes mounts the transfer-record change feed on the web engine,
// gated by Pelican's own token authentication.
//
// The upstream handler is transport-neutral and expects to be token-gated in
// front, which is exactly how Pelican already protects its other monitoring
// endpoints. A collector subscribes over SSE and acknowledges what it has
// durably stored; the acknowledgement is what lets this server know how far the
// collector has got.
//
// Authorization requires monitoring.scrape. Note that this is the same scope
// that grants Prometheus scraping, and transfer records are more revealing than
// aggregate metrics -- they carry object paths, client addresses, and user
// identities. A deployment that wants those held to a narrower audience than its
// metrics needs a distinct scope; that is a policy decision rather than a
// mechanism one, and the mechanism here would not change.
func (s *Store) RegisterFeedRoutes(router *gin.RouterGroup) {
	handler := changefeed.Handler(s.cat, changefeed.ServerOptions{
		// Identity has already been established by the middleware below; this
		// only reads it back out. Returning ok=false here would be a bug rather
		// than a rejection, since an unauthenticated request cannot reach it.
		Auth: func(r *http.Request) (string, string, bool) {
			subscriber, ok := r.Context().Value(subscriberContextKey{}).(string)
			if !ok || subscriber == "" {
				return "", "", false
			}
			return s.cfg.Identity.Name, subscriber, true
		},
		// The record attribute the feed stamps as an event timestamp, which is
		// what lets acknowledgements translate into a garbage-collection floor.
		AgeAttr:   AttrCompletionDate,
		Heartbeat: 15 * time.Second,
	})

	group := router.Group(FeedRoutePrefix, s.authenticateSubscriber)
	group.Any("/*any", gin.WrapH(http.StripPrefix(FeedRoutePrefix, handler)))
}

// authenticateSubscriber verifies the caller's token and records who they are.
//
// The subscriber identity comes from the token's subject rather than from a
// request parameter. That matters for more than tidiness: acknowledgements
// advance a garbage-collection floor, so a client able to name itself freely
// could acknowledge on another subscriber's behalf and cause records to be
// dropped before that subscriber had collected them.
func (s *Store) authenticateSubscriber(ctx *gin.Context) {
	result, status, ok, err := token.VerifyAndExtract(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.FederationIssuer, token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Monitoring_Scrape},
	})
	if !ok {
		msg := "authentication required to read transfer records"
		if err != nil {
			msg = err.Error()
		}
		ctx.AbortWithStatusJSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
		})
		return
	}

	subscriber := ""
	if result != nil && result.Token != nil {
		subscriber = result.Token.Subject()
	}
	if subscriber == "" {
		// A token that authenticates but names no subject cannot be given a
		// durable cursor, because there is nothing stable to attribute
		// acknowledgements to. Refusing is better than sharing one anonymous
		// cursor between unrelated collectors.
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "the presented token has no subject; a change-feed subscriber must be identifiable",
		})
		return
	}

	log.Debugf("Transfer-record feed request from subscriber %q", subscriber)
	ctx.Request = ctx.Request.WithContext(
		contextWithSubscriber(ctx.Request.Context(), subscriber))
	ctx.Next()
}
