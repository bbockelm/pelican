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
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/changefeed"
	"github.com/PelicanPlatform/classad/db/replicate"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// memSink is the smallest possible collector: it keeps changes in memory and
// remembers its cursor. A real central monitoring service differs only in where
// it puts them.
type memSink struct {
	mu      sync.Mutex
	changes []replicate.Change
	cursor  []byte
	resets  []replicate.ResetReason
}

func (m *memSink) Apply(c replicate.Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch c.Kind {
	case replicate.KindUpsert:
		m.changes = append(m.changes, c)
	case replicate.KindReset:
		// A real collector keeps these: a Reset means discard and rebuild, and
		// its reason is the difference between records it LOST and records it
		// is merely being sent again.
		m.resets = append(m.resets, c.Reason)
	}
	return nil
}

// Commit is where a real collector would durably record its position; the
// cursor is what makes an outage survivable rather than a data gap.
func (m *memSink) Commit(cursor []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursor = cursor
	return nil
}

func (m *memSink) Cursor() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursor
}

func (m *memSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.changes)
}

func (m *memSink) resetReasons() []replicate.ResetReason {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]replicate.ResetReason(nil), m.resets...)
}

// feedServer stands the change feed up on a real HTTP listener with the
// authenticating middleware replaced by a stub, so these tests exercise the
// wiring and the feed rather than Pelican's token machinery (which has its own
// tests, and which needs a federation to issue against).
func feedServer(t *testing.T, s *Store, subscriber string) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	group := engine.Group("")

	handler := changefeed.Handler(s.cat, changefeed.ServerOptions{
		Auth: func(r *http.Request) (string, string, bool) {
			if subscriber == "" {
				return "", "", false
			}
			return s.cfg.Identity.Name, subscriber, true
		},
		AgeAttr: AttrCompletionDate,
	})
	group.Any(FeedRoutePrefix+"/*any",
		gin.WrapH(http.StripPrefix(FeedRoutePrefix, handler)))

	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return srv
}

// TestChangefeedDeliversRecords is the end-to-end contract: a record written to
// the archive reaches a subscriber that pulls the feed.
func TestChangefeedDeliversRecords(t *testing.T) {
	s := openStore(t)
	s.Record(sampleEvent())
	s.Record(sampleEvent())

	srv := feedServer(t, s, "collector-1")
	sink := &memSink{}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- changefeed.Pull(ctx, changefeed.PullConfig{
			BaseURL: srv.URL + FeedRoutePrefix,
			Table:   ArchiveTableName,
			Src:     s.cfg.Identity.Name,
		}, sink)
	}()

	require.Eventually(t, func() bool { return sink.count() >= 2 }, 15*time.Second, 100*time.Millisecond,
		"the subscriber never received the archived records")
	cancel()
	require.NoError(t, <-done)
}

// TestChangefeedRejectsUnauthenticated checks that the feed is closed to a
// caller the authorizer will not identify. Transfer records carry user
// identities and object paths, so an open feed would be a disclosure.
func TestChangefeedRejectsUnauthenticated(t *testing.T) {
	s := openStore(t)
	s.Record(sampleEvent())

	srv := feedServer(t, s, "") // the authorizer refuses everyone

	req, err := http.NewRequest(http.MethodGet,
		srv.URL+FeedRoutePrefix+changefeed.PathSubscribe+"?table="+ArchiveTableName, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"an unidentified caller must not be able to read transfer records")
}

// TestChangefeedResumesFromCursor is what makes a collector outage survivable:
// a subscriber that reconnects with a stored cursor gets what it missed and not
// what it already has.
func TestChangefeedResumesFromCursor(t *testing.T) {
	s := openStore(t)
	s.Record(sampleEvent())

	srv := feedServer(t, s, "collector-1")
	sink := &memSink{}

	// First connection: collect the initial record, then disconnect.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Second)
	done1 := make(chan error, 1)
	go func() {
		done1 <- changefeed.Pull(ctx1, changefeed.PullConfig{
			BaseURL: srv.URL + FeedRoutePrefix, Table: ArchiveTableName, Src: s.cfg.Identity.Name,
		}, sink)
	}()
	require.Eventually(t, func() bool { return sink.count() >= 1 }, 15*time.Second, 100*time.Millisecond)
	cancel1()
	require.NoError(t, <-done1)

	cursor := sink.Cursor()
	require.NotEmpty(t, cursor, "a subscriber must retain a resumable position")
	before := sink.count()

	// More transfers happen while the subscriber is away.
	s.Record(sampleEvent())
	s.Record(sampleEvent())

	// Second connection, same sink and therefore same cursor.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel2()
	done2 := make(chan error, 1)
	go func() {
		done2 <- changefeed.Pull(ctx2, changefeed.PullConfig{
			BaseURL: srv.URL + FeedRoutePrefix, Table: ArchiveTableName, Src: s.cfg.Identity.Name,
		}, sink)
	}()
	require.Eventually(t, func() bool { return sink.count() >= before+2 }, 15*time.Second, 100*time.Millisecond,
		"records written during the outage were not delivered on reconnect")
	cancel2()
	require.NoError(t, <-done2)

	assert.Equal(t, 3, sink.count(),
		"resuming from a cursor must not redeliver records the subscriber already had")
}

// pullUntil runs a subscriber against srv until the sink holds want records and
// has committed a position, then disconnects it the way a collector outage
// would. Waiting for the cursor as well as the records is deliberate: the
// cursor is what the next connection resumes from, and it is committed at the
// Synced that follows catch-up, not with the records themselves.
func pullUntil(t *testing.T, srv *httptest.Server, s *Store, table string, sink *memSink, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- changefeed.Pull(ctx, changefeed.PullConfig{
			BaseURL: srv.URL + FeedRoutePrefix, Table: table, Src: s.cfg.Identity.Name,
		}, sink)
	}()
	require.Eventually(t, func() bool { return sink.count() >= want && len(sink.Cursor()) > 0 },
		15*time.Second, 100*time.Millisecond,
		"the subscriber never reached %d records with a committed cursor", want)
	cancel()
	require.NoError(t, <-done)
}

// TestChangefeedResumesAcrossAServerRestart is the restart case, and the reason
// TestChangefeedResumesFromCursor is not enough by itself: that test keeps the
// store open and only disconnects the subscriber, so it cannot see whether the
// position a collector persisted still means anything once the server it came
// from has stopped and started. For a long time it did not -- a restart
// invalidated every cursor, and a collector that had been following a server
// for months was handed the whole retained archive again the first time that
// server was upgraded.
//
// The archive carries its watch epoch across a CLEAN shutdown, which is why
// this test closes the store rather than abandoning it.
func TestChangefeedResumesAcrossAServerRestart(t *testing.T) {
	cfg := Config{Dir: t.TempDir(), Identity: testIdentity(), RotateInterval: -1, MaintainInterval: -1}
	sink := &memSink{}

	first, err := Open(cfg)
	require.NoError(t, err)
	first.Record(sampleEvent())
	pullUntil(t, feedServer(t, first, "collector-1"), first, ArchiveTableName, sink, 1)
	require.NoError(t, first.Close(), "a clean shutdown is what lets the watch epoch survive")

	require.Equal(t, []replicate.ResetReason{replicate.ResetInitial}, sink.resetReasons(),
		"a first subscribe is a reset, and it must say which kind: nothing was missed")

	// The server comes back on the same directory and records another transfer.
	second, err := Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, second.Close()) }()
	second.Record(sampleEvent())

	pullUntil(t, feedServer(t, second, "collector-1"), second, ArchiveTableName, sink, 2)

	assert.Equal(t, 2, sink.count(),
		"a restart must not redeliver records the subscriber already had")
	assert.Equal(t, []replicate.ResetReason{replicate.ResetInitial}, sink.resetReasons(),
		"a cursor that survived a clean restart must not be reset a second time")
}

// TestActiveTableCursorSurvivesARestart pins what the watch-retention window
// buys, and is the falsification of the archive test above: the two arms differ
// only in whether the window is configured, and only one of them resumes.
//
// The active table is mutable, so a subscriber resuming after a restart has to
// be told which rows went away while it was gone. That is what the delete
// markers in the window are for; with no window the source cannot prove what it
// removed, and the only honest answer is to reset the subscriber and send the
// table again.
func TestActiveTableCursorSurvivesARestart(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retain     time.Duration
		wantResets []replicate.ResetReason
		wantRows   int
	}{
		{
			name:       "with the default window",
			retain:     0, // DefaultWatchRetain
			wantResets: []replicate.ResetReason{replicate.ResetInitial},
			wantRows:   2,
		},
		{
			name:       "without a window",
			retain:     -1,
			wantResets: []replicate.ResetReason{replicate.ResetInitial, replicate.ResetEpoch},
			wantRows:   3, // the first row again, then both
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Dir: t.TempDir(), Identity: testIdentity(),
				RotateInterval: -1, MaintainInterval: -1, WatchRetain: tc.retain,
			}
			sink := &memSink{}

			first, err := Open(cfg)
			require.NoError(t, err)
			require.NotEmpty(t, first.BeginActive(sampleEvent()))
			pullUntil(t, feedServer(t, first, "collector-1"), first, ActiveTableName, sink, 1)
			require.NoError(t, first.Close())

			second, err := Open(cfg)
			require.NoError(t, err)
			defer func() { require.NoError(t, second.Close()) }()
			require.NotEmpty(t, second.BeginActive(sampleEvent()))

			pullUntil(t, feedServer(t, second, "collector-1"), second, ActiveTableName, sink, tc.wantRows)

			assert.Equal(t, tc.wantResets, sink.resetReasons())
			assert.Equal(t, tc.wantRows, sink.count())
		})
	}
}

// authenticatedFeedServer stands the feed up with the real authenticating
// middleware -- token.VerifyAndExtract and the monitoring.scrape check -- rather
// than the stub used above.
func authenticatedFeedServer(t *testing.T, s *Store) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	s.RegisterFeedRoutes(engine.Group(""))
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return srv
}

// mintFeedToken issues a token the running server will accept, signed by the
// issuer key the test configured.
func mintFeedToken(t *testing.T, issuer, subject string, scopes ...token_scopes.TokenScope) string {
	t.Helper()
	tk := token.NewWLCGToken()
	tk.Issuer = issuer
	tk.Subject = subject
	tk.Lifetime = 5 * time.Minute
	tk.AddAudiences(issuer)
	tk.AddScopes(scopes...)
	tok, err := tk.CreateToken()
	require.NoError(t, err)
	return tok
}

// setupIssuer configures a local issuer so tokens can be minted and verified in
// this process, and returns its URL.
func setupIssuer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(dir, "issuer-keys")))
	const issuer = "https://pelican.example.org"
	require.NoError(t, param.Server_ExternalWebUrl.Set(issuer))
	_, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	return issuer
}

// TestAuthenticatedPull closes the gap the earlier tests left: every piece was
// exercised separately -- a real Pull against a stubbed authorizer, and a real
// authorizer refusing an anonymous caller -- but never together. This drives a
// real subscriber through the real middleware with a real token.
func TestAuthenticatedPull(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	issuer := setupIssuer(t)

	s := openStore(t)
	s.Record(sampleEvent())
	s.Record(sampleEvent())

	srv := authenticatedFeedServer(t, s)
	sink := &memSink{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- changefeed.Pull(ctx, changefeed.PullConfig{
			BaseURL:    srv.URL + FeedRoutePrefix,
			Table:      ArchiveTableName,
			Src:        s.cfg.Identity.Name,
			Subscriber: "collector-1",
			Token:      mintFeedToken(t, issuer, "collector-1", token_scopes.Monitoring_Raw),
		}, sink)
	}()

	require.Eventually(t, func() bool { return sink.count() >= 2 }, 20*time.Second, 100*time.Millisecond,
		"an authenticated subscriber never received the records")
	cancel()
	require.NoError(t, <-done)
}

// TestPullRejectedWithoutScope checks that authentication alone is not enough,
// and specifically that monitoring.scrape does not open this feed. Someone
// permitted to scrape a server's metrics must not thereby be able to read who
// transferred what; that separation is the entire reason monitoring.raw exists,
// so it is worth a test rather than a comment.
func TestPullRejectedWithoutScope(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	issuer := setupIssuer(t)

	s := openStore(t)
	s.Record(sampleEvent())
	srv := authenticatedFeedServer(t, s)

	// A valid token carrying monitoring.scrape -- enough to read this server's
	// metrics, and deliberately not enough to read its transfer records.
	tok := mintFeedToken(t, issuer, "collector-1", token_scopes.Monitoring_Scrape)

	req, err := http.NewRequest(http.MethodGet,
		srv.URL+FeedRoutePrefix+changefeed.PathSubscribe+"?table="+ArchiveTableName, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.GreaterOrEqual(t, resp.StatusCode, 400,
		"a token without the monitoring scope must not read transfer records")
	// Specifically a scope denial, not an incidental failure: the same token
	// authenticates fine, so only the missing scope can be turning it away.
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
